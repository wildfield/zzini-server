const std = @import("std");

const max_token_size = 1024;
const max_path_size = 1024;
const max_header_size = 32 * 1024;
const max_etag_size = 512;

pub const Error = error{
    header_too_long,
    token_too_long,
    unexpected_token,
    unsupported_protocol,
    unexpected_whitespace,
    unexpected_carriage_return,
    unexpected_byte,
    drained,
};

pub const ContentError = error{
    unsupported_method,
    path_too_long,
    etag_too_long,
};

const Token = enum {
    method,
    path,
    protocol,
    header_key,
    header_value,
    end_line,
    whitespace,
    drain,
};

const Method = enum { get, head };

pub const ResettableState = struct {
    in_progress_token_len: usize = 0,
    parsed_last_token: ?Token = null,
    current_token: Token = .method,
    path_len: usize = 0,
    total_bytes_scanned: usize = 0,
    parsing_done: bool = false,
    etag_len: usize = 0,
    expecting_etag: bool = false,
    method: Method = .get,
    // Represents errors where the header is parsable, but the content is somehow wrong
    content_error: ?ContentError = null,
};

// Buffer -> a bunch of lines -> each line contains a value -> limited size buffers
pub const State = struct {
    allocator: std.mem.Allocator,
    in_progress_token_buf: []u8,
    path_buf: []u8,
    etag_buf: []u8,
    state: ResettableState = .{},

    pub fn init(allocator: std.mem.Allocator) !State {
        return .{
            .allocator = allocator,
            .in_progress_token_buf = try allocator.alloc(u8, max_token_size),
            .path_buf = try allocator.alloc(u8, max_path_size),
            .etag_buf = try allocator.alloc(u8, max_etag_size),
            .state = .{},
        };
    }

    pub fn deinit(self: State) void {
        self.allocator.free(self.in_progress_token_buf);
        self.allocator.free(self.path_buf);
        self.allocator.free(self.etag_buf);
    }

    pub fn reset(self: *State) void {
        self.state = .{};
    }

    inline fn isWhitespace(byte: u8) bool {
        // I consider : to be whitespace for simplicity
        return byte == ' ' or byte == '\t' or byte == ':';
    }

    fn skipByte(self: *State) !void {
        self.state.total_bytes_scanned += 1;
        if (self.state.total_bytes_scanned > max_header_size) {
            return Error.header_too_long;
        }
    }

    fn addByte(self: *State, byte: u8) !void {
        self.state.total_bytes_scanned += 1;
        if (self.state.total_bytes_scanned > max_header_size) {
            return Error.header_too_long;
        }
        if (self.state.in_progress_token_len >= self.in_progress_token_buf.len) {
            return Error.token_too_long;
        }
        self.in_progress_token_buf[self.state.in_progress_token_len] = byte;
        self.state.in_progress_token_len += 1;
    }

    fn prepareForNextToken(self: *State, next: Token) void {
        self.state.in_progress_token_len = 0;
        self.state.parsed_last_token = self.state.current_token;
        self.state.current_token = next;
    }

    fn getCurrentToken(self: *State) []u8 {
        return self.in_progress_token_buf[0..self.state.in_progress_token_len];
    }

    // Returns scanned header length if parsing is done, otherwise returns full buffer length
    pub fn parse(self: *State, buffer: []const u8) Error!usize {
        for (0..buffer.len) |idx| {
            const byte = buffer[idx];
            switch (self.state.current_token) {
                .method => {
                    if (!isWhitespace(byte)) {
                        if (byte == '\r') {
                            return Error.unexpected_carriage_return;
                        } else {
                            try self.addByte(byte);
                        }
                    } else {
                        const token = self.getCurrentToken();
                        if (std.mem.eql(u8, token, "GET")) {
                            self.state.method = .get;
                            self.prepareForNextToken(.whitespace);
                            try self.skipByte();
                        } else if (std.mem.eql(u8, token, "HEAD")) {
                            self.state.method = .head;
                            self.prepareForNextToken(.whitespace);
                            try self.skipByte();
                        } else {
                            self.state.content_error = ContentError.unsupported_method;
                            self.prepareForNextToken(.drain);
                            try self.skipByte();
                        }
                    }
                },
                .whitespace => {
                    // End whitespace parsing on first non-whitespace byte
                    if (!isWhitespace(byte)) {
                        if (byte == '\r') {
                            return Error.unexpected_carriage_return;
                        } else if (self.state.parsed_last_token) |token_type| {
                            const next_token: Token = switch (token_type) {
                                .whitespace => {
                                    unreachable;
                                },
                                .method => .path,
                                .path => .protocol,
                                .header_key => .header_value,
                                else => {
                                    return Error.unexpected_token;
                                },
                            };
                            self.state.parsed_last_token = .whitespace;
                            self.state.current_token = next_token;
                            // Don't lose the byte
                            try self.addByte(byte);
                        } else {
                            std.debug.assert(false);
                        }
                    } else {
                        try self.skipByte();
                    }
                },
                .path => {
                    if (!isWhitespace(byte)) {
                        if (byte == '\r') {
                            return Error.unexpected_carriage_return;
                        } else {
                            try self.addByte(byte);
                        }
                    } else {
                        const token = self.getCurrentToken();
                        if (token.len > self.path_buf.len) {
                            self.state.content_error = ContentError.path_too_long;
                            self.prepareForNextToken(.drain);
                            try self.skipByte();
                            continue;
                        }
                        @memcpy(self.path_buf[0..token.len], token);
                        self.state.path_len = token.len;
                        std.log.debug("path_buf {s}", .{self.path_buf[0..self.state.path_len]});

                        // Preparing clears the data
                        self.prepareForNextToken(.whitespace);
                        try self.skipByte();
                    }
                },
                .protocol => {
                    if (!isWhitespace(byte)) {
                        if (byte != '\r') {
                            try self.addByte(byte);
                        } else {
                            const token = self.getCurrentToken();
                            if (std.mem.eql(u8, token, "HTTP/1.1")) {
                                self.prepareForNextToken(.end_line);
                                try self.skipByte();
                            } else {
                                return Error.unsupported_protocol;
                            }
                        }
                    } else {
                        return Error.unexpected_whitespace;
                    }
                },
                .end_line => {
                    if (byte == '\r') {
                        try self.skipByte();
                    } else if (byte == '\n') {
                        if (self.state.parsed_last_token) |token_type| {
                            const next_token: Token = switch (token_type) {
                                .whitespace => {
                                    unreachable;
                                },
                                .end_line => {
                                    // Double end line, we are done
                                    self.state.parsing_done = true;
                                    // Return parsed length
                                    return idx + 1;
                                },
                                .protocol => .header_key,
                                .header_value => .header_key,
                                else => {
                                    return Error.unexpected_token;
                                },
                            };
                            self.state.parsed_last_token = .end_line;
                            self.state.current_token = next_token;
                        } else {
                            return Error.unexpected_token;
                        }
                        try self.skipByte();
                    } else {
                        std.log.debug("Unexpected byte: {}", .{byte});
                        return Error.unexpected_byte;
                    }
                },
                .header_key => {
                    if (!isWhitespace(byte)) {
                        if (byte == '\r') {
                            // This is a special case where we don't have the next header key
                            // it only makes sense if there's no key at all
                            if (self.state.in_progress_token_len == 0) {
                                self.state.current_token = .end_line;
                                try self.skipByte();
                            } else {
                                return Error.unexpected_carriage_return;
                            }
                        } else {
                            try self.addByte(byte);
                        }
                    } else if (self.state.in_progress_token_len > 0) {
                        // TODO actual handling
                        const token = self.getCurrentToken();
                        std.log.debug("Parsed header key: {s}", .{token});
                        _ = std.ascii.lowerString(token, token);
                        if (std.mem.eql(u8, token, "if-none-match")) {
                            self.state.expecting_etag = true;
                        }
                        self.prepareForNextToken(.whitespace);
                    } else {
                        return Error.unexpected_whitespace;
                    }
                },
                .header_value => {
                    // Whitespace is allowed for header values
                    if (byte == '\r') {
                        if (self.state.in_progress_token_len > 0) {
                            // TODO actual handling
                            const token = self.getCurrentToken();
                            std.log.debug("Parsed header value: {s}", .{token});
                            if (self.state.expecting_etag) {
                                self.state.expecting_etag = false;
                                if (token.len > max_etag_size) {
                                    self.state.content_error = ContentError.etag_too_long;
                                    self.prepareForNextToken(.drain);
                                    try self.skipByte();
                                    continue;
                                } else if (token.len > 0) {
                                    @memcpy(self.etag_buf[0..token.len], token);
                                    self.state.etag_len = token.len;
                                }
                            }
                            self.prepareForNextToken(.end_line);
                            try self.skipByte();
                        } else {
                            return Error.unexpected_carriage_return;
                        }
                    } else {
                        try self.addByte(byte);
                    }
                },
                .drain => {
                    // Special case when we encounter an error but we want to finish processing header
                    // We just wait for \r\n\r\n then stop
                    const token_len = self.state.in_progress_token_len;
                    if (byte == '\r' and (token_len == 0 or token_len == 2)) {
                        try self.addByte(byte);
                    } else if (byte == '\n' and token_len == 1) {
                        try self.addByte(byte);
                    } else if (byte == '\n' and token_len == 3) {
                        // We are done draining
                        return Error.drained;
                    } else {
                        try self.skipByte();
                        self.state.in_progress_token_len = 0;
                    }
                },
            }
        }
        return buffer.len;
    }
};
