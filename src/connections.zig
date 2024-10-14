const std = @import("std");

const keys = @import("keys.zig");
const command = @import("command.zig");
pub const ssl = keys.ssl;
const parser = @import("parser.zig");
const config = @import("config.zig");

const buffer_size = ssl.BR_SSL_BUFSIZE_MONO;
pub const max_connections = 1 << config.index_bits;

pub const IOOperationType = enum(u3) { accept, read, write, close, timeout };

// All operations except for accept also contain a connection index
pub const IOOperation = union(IOOperationType) {
    // accept: true if encrypted, false if unencrypted
    accept: bool,
    read: usize,
    write: usize,
    close: usize,
    timeout: void,
};

pub const Connection = struct {
    socket: std.posix.fd_t = 0,
    is_closing_gracefully: bool = false,
    is_closing: bool = false,
    is_ssl: bool = true,
    // if null, it means we are reading
    writer_state: ?command.WriteDataCommand = null,
    non_ssl_read_bytes_pending: usize = 0,
    non_ssl_write_bytes_pending: usize = 0,
    non_ssl_write_bytes_done: usize = 0,
};

pub const Connections = struct {
    allocator: std.mem.Allocator,
    busy: []bool,
    connections: []Connection,
    ssl_contexts: []ssl.br_ssl_server_context,
    ssl_buffers: [][]u8,
    ssl_cache_buffer: []u8,
    ssl_cache_context: *ssl.br_ssl_session_cache_lru,

    parsers: []parser.State,

    certs: []ssl.br_x509_certificate,
    private_key: *ssl.br_rsa_private_key,
    procotol_names: [][*c]const u8,
    is_accept_ssl_bottlenecked: bool,
    is_accept_non_ssl_bottlenecked: bool,
    busy_connections_count: usize,

    // Small optimization to reduce scanning time
    earliest_free_index: usize,

    pub fn init(allocator: std.mem.Allocator, key: keys.Keys) !Connections {
        var result: Connections = undefined;
        result.allocator = allocator;
        result.busy = try allocator.allocWithOptions(bool, max_connections, null, false);
        result.connections = try allocator.allocWithOptions(Connection, max_connections, null, .{});
        result.ssl_contexts = try allocator.alloc(ssl.br_ssl_server_context, max_connections);
        result.parsers = try allocator.alloc(parser.State, max_connections);
        result.ssl_buffers = try allocator.alloc([]u8, max_connections);
        result.ssl_cache_context = try allocator.create(ssl.br_ssl_session_cache_lru);
        result.ssl_cache_buffer = try allocator.alloc(u8, max_connections * 100);
        // Supported protocols
        result.procotol_names = try allocator.alloc([*c]u8, 1);
        result.procotol_names[0] = @ptrCast("http/1.1");
        result.is_accept_ssl_bottlenecked = false;
        result.is_accept_non_ssl_bottlenecked = false;
        result.busy_connections_count = 0;
        result.earliest_free_index = 0;

        for (0..result.parsers.len) |idx| {
            result.parsers[idx] = try parser.State.init(allocator);
        }

        for (0..result.ssl_buffers.len) |idx| {
            result.ssl_buffers[idx] = try allocator.alloc(u8, buffer_size);
        }

        // Initialize BearSSl
        result.certs = try allocator.alloc(ssl.br_x509_certificate, key.certs.len);
        for (0..key.certs.len) |i| {
            const cert = key.certs[i];
            result.certs[i] = .{ .data = cert.ptr, .data_len = cert.len };
        }
        ssl.br_ssl_session_cache_lru_init(result.ssl_cache_context, result.ssl_cache_buffer.ptr, result.ssl_cache_buffer.len);
        for (0..result.ssl_contexts.len) |idx| {
            switch (key.private_key) {
                .rsa => |rsa_key| {
                    ssl.br_ssl_server_init_full_rsa(
                        &result.ssl_contexts[idx],
                        result.certs.ptr,
                        result.certs.len,
                        rsa_key,
                    );
                },
                .ec => |ec_key| {
                    ssl.br_ssl_server_init_full_ec(
                        &result.ssl_contexts[idx],
                        result.certs.ptr,
                        result.certs.len,
                        @intCast(ec_key.key_type),
                        ec_key.key,
                    );
                },
            }
            ssl.br_ssl_engine_set_buffer(
                &result.ssl_contexts[idx].eng,
                result.ssl_buffers[idx].ptr,
                result.ssl_buffers[idx].len,
                0,
            );
            ssl.br_ssl_server_set_cache(&result.ssl_contexts[idx], @ptrCast(result.ssl_cache_context));
            ssl.br_ssl_engine_set_protocol_names(&result.ssl_contexts[idx].eng, result.procotol_names.ptr, 1);
        }
        return result;
    }

    pub fn deinit(self: *Connections) void {
        self.allocator.free(self.ssl_contexts);
        self.allocator.free(self.ssl_cache_context);
        self.allocator.free(self.ssl_cache_buffer);

        for (0..self.parsers) |idx| {
            self.parsers[idx].deinit();
        }
        self.allocator.free(self.parsers);

        for (0..self.ssl_buffers.len) |idx| {
            self.allocator.free(self.ssl_buffers[idx]);
        }
        self.allocator.free(self.ssl_buffers);

        self.allocator.free(self.busy);
        self.allocator.free(self.connections);
        self.allocator.free(self.cert);
        self.allocator.free(self.private_key);
    }

    pub fn nextFreeIndex(self: *const Connections) ?usize {
        for (self.earliest_free_index..self.busy.len) |idx| {
            if (self.busy[idx] == false) {
                return idx;
            }
        }

        return null;
    }
};

// Encodes operation to user data for IOUring
pub fn encode(op: IOOperation) u64 {
    return switch (op) {
        IOOperationType.accept => |encrypted| {
            const op_code: u64 = 0;
            return (op_code << config.index_bits) | @intFromBool(encrypted);
        },
        IOOperationType.close => |index| {
            const op_code: u64 = @intCast(@intFromEnum(IOOperationType.close));
            return (op_code << config.index_bits) | index;
        },
        IOOperationType.read => |index| {
            const op_code: u64 = @intCast(@intFromEnum(IOOperationType.read));
            return (op_code << config.index_bits) | index;
        },
        IOOperationType.write => |index| {
            const op_code: u64 = @intCast(@intFromEnum(IOOperationType.write));
            return (op_code << config.index_bits) | index;
        },
        IOOperationType.timeout => {
            const op_code: u64 = @intCast(@intFromEnum(IOOperationType.timeout));
            return (op_code << config.index_bits);
        },
    };
}

// Decodes operation to user data for IOUring
pub fn decode(op: u64) IOOperation {
    const index_mask: u64 = comptime ~(@shlWithOverflow(@as(u64, std.math.maxInt(u64)), config.index_bits)[0]);
    const index = op & index_mask;
    const op_type_code = op >> config.index_bits;
    const op_type: IOOperationType = @enumFromInt(op_type_code);
    return switch (op_type) {
        IOOperationType.accept => IOOperation{ .accept = if (index == 0) false else true },
        IOOperationType.close => IOOperation{ .close = index },
        IOOperationType.read => IOOperation{ .read = index },
        IOOperationType.write => IOOperation{ .write = index },
        IOOperationType.timeout => IOOperation.timeout,
    };
}
