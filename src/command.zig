const std = @import("std");

pub const CommandType = enum(u8) {
    write_data,
    check_status,
};

pub const HttpError = enum {
    not_found,
    unsupported_method,
    cache_hit,

    pub fn statusLine(self: HttpError) []const u8 {
        return switch (self) {
            .not_found => "HTTP/1.1 404 Not Found\r\n",
            .unsupported_method => "HTTP/1.1 405 Method Not Allowed\r\n",
            .cache_hit => "HTTP/1.1 304 Not Modified\r\n",
        };
    }

    pub fn fileName(self: HttpError) ?[]const u8 {
        return switch (self) {
            .not_found => "/_error/404.html",
            .unsupported_method => null,
            .cache_hit => null,
        };
    }

    // 304 needs a slightly different header compared to an empty error
    pub fn isCacheHit(self: HttpError) bool {
        return switch (self) {
            .not_found => false,
            .unsupported_method => false,
            .cache_hit => true,
        };
    }
};

pub const WriteDataType = enum { file_idx, err, ssl_redirect };

pub const WriteData = union(WriteDataType) {
    file_idx: usize,
    err: HttpError,
    // Argument: requested location
    ssl_redirect: []const u8,
};

pub const WriteDataCommand = struct {
    index: usize,
    data: WriteData,
    was_status_written: bool = false,
    was_header_written: bool = false,
    file_bytes_written: usize = 0,
    should_add_etag: bool = true,
    is_head_method: bool = false,
};

pub const FileReaderStateType = enum {
    open_file,
    read_file,
    close_file,
};

pub const OpenFileState = struct {
    path: [:0]const u8,
    len: usize,
};

pub const ReadFileState = struct {
    handle: std.posix.fd_t,
    offset: usize,
    len: usize,
};

pub const FileReaderState = union(FileReaderStateType) {
    open_file: OpenFileState,
    read_file: ReadFileState,
    // file handle
    close_file: std.posix.fd_t,
};
