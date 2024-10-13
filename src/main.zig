const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const net = std.net;

const connections = @import("connections.zig");
const keys = @import("keys.zig");
const ssl = connections.ssl;
const command = @import("command.zig");
const parser = @import("parser.zig");
const files = @import("files.zig");
const config = @import("config.zig");
const pem_loader = @import("pem_loader.zig");

const c = @cImport({
    @cInclude("time.h");
});

// Global options. This sets global log level to info
pub const std_options = .{
    .log_level = .debug,
};

// const tracy = @cImport({
//     // @cDefine("TRACY_ENABLE", {});
//     // @cDefine("TRACY_ON_DEMAND", {});
//     // @cInclude("tracy/TracyC.h");
// });

inline fn tracyMarkStart(name: [*c]const u8) void {
    _ = name;
    // tracy.___tracy_emit_frame_mark_start(name);
}

inline fn tracyMarkEnd(name: [*c]const u8) void {
    _ = name;
    // tracy.___tracy_emit_frame_mark_end(name);
}

pub const max_connections = connections.max_connections;

const CurrentArgument = enum {
    hostname,
    public_folder,
    certificate_public_key,
    certificate_private_key,
    done,

    pub fn next(self: CurrentArgument) CurrentArgument {
        return switch (self) {
            .hostname => .public_folder,
            .public_folder => .certificate_public_key,
            .certificate_public_key => .certificate_private_key,
            .certificate_private_key => .done,
            .done => .done,
        };
    }
};

// Sqe ring size.
// Each connection can have at most 1 request
// + at most 2 accept requests
// However, sqe demands power of 2 entries
pub const max_entries = max_connections << 1;

pub fn main() !u8 {
    tracyMarkStart("main");
    defer {
        tracyMarkEnd("main");
    }
    var args = std.process.args();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer {
        _ = gpa.detectLeaks();
    }

    const executable = args.next().?;
    var current_arg: CurrentArgument = .hostname;
    var file_index_map: ?files.FileIndexMap = null;
    var file_storage: ?[]const files.FileInfo = null;
    var hostname: []const u8 = undefined;

    // Deferred buffers to deallocate in the outer scope
    var deferred_buffers = std.ArrayList([]u8).init(allocator);
    defer {
        for (deferred_buffers.items) |item| {
            allocator.free(item);
        }
        deferred_buffers.deinit();
    }

    var cert_buffers: ?[][]u8 = null;
    defer {
        if (cert_buffers) |buffers| {
            allocator.free(buffers);
        }
    }

    var key_decoder: ssl.br_skey_decoder_context = undefined;

    while (args.next()) |filename| {
        switch (current_arg) {
            .done => {
                // We should never reach this because the server setup should return on completion
                std.log.err("Reached done state in the arg parsing", .{});
                return 1;
            },
            .hostname => {
                hostname = filename;
            },
            .public_folder => {
                // Read files
                const load_files_result = try files.loadFiles(allocator, filename);
                file_index_map = load_files_result.file_index_map;
                file_storage = load_files_result.file_storage;
                try deferred_buffers.append(load_files_result.buffer);
                std.log.info("File cache used (bytes): {} / {}", .{ load_files_result.buffer.len, config.total_cache_size });

                // Check if we have files for every possible error
                inline for (std.meta.fields(command.HttpError)) |field| {
                    const val: command.HttpError = @enumFromInt(field.value);
                    const filename_or_null = val.fileName();
                    if (filename_or_null) |filename_check| {
                        if (!file_index_map.?.contains(filename_check)) {
                            std.log.err("Misssing error file {s}", .{filename_check});
                            return 1;
                        }
                    }
                }
            },
            .certificate_public_key => {
                cert_buffers = try pem_loader.read_pem(allocator, filename);
                for (cert_buffers.?) |buffer| {
                    try deferred_buffers.append(buffer);
                }
            },
            .certificate_private_key => {
                const pem_buffers = try pem_loader.read_pem(allocator, filename);
                defer {
                    allocator.free(pem_buffers);
                }
                if (pem_buffers.len != 1) {
                    std.log.err("More than 1 private key. Expected a single private key", .{});
                    return 1;
                }
                defer {
                    allocator.free(pem_buffers[0]);
                }

                ssl.br_skey_decoder_init(&key_decoder);
                ssl.br_skey_decoder_push(&key_decoder, pem_buffers[0].ptr, pem_buffers[0].len);
            },
        }

        current_arg = current_arg.next();
        if (current_arg == .done) {
            // We are done working with arguments, start server
            // Key setup
            var private_key: keys.PrivateKey = undefined;
            const key_type = ssl.br_skey_decoder_key_type(&key_decoder);
            const ec_key: ?*const ssl.br_ec_private_key = ssl.br_skey_decoder_get_ec(&key_decoder);
            const rsa_key: ?*const ssl.br_rsa_private_key = ssl.br_skey_decoder_get_rsa(&key_decoder);
            if (ec_key) |ec_key_unwrapped| {
                private_key = .{ .ec = .{ .key = ec_key_unwrapped, .key_type = key_type } };
            } else if (rsa_key) |rsa_key_unwrapped| {
                private_key = .{ .rsa = rsa_key_unwrapped };
            } else {
                std.log.err("Unsupported key type: {}", .{key_type});
                return 1;
            }

            const key = keys.Keys{
                .certs = cert_buffers.?,
                .private_key = private_key,
            };

            // Network setup
            // SSL socket
            const sock_ssl = try posix.socket(posix.AF.INET6, posix.SOCK.STREAM, 0);
            defer {
                posix.close(sock_ssl);
            }

            {
                errdefer {
                    std.log.err("Failed to setup SSL listener on port {}", .{config.ssl_port});
                }

                try posix.setsockopt(sock_ssl, posix.SOL.SOCKET, posix.SO.REUSEPORT, &std.mem.toBytes(@as(c_int, 1)));
                try posix.setsockopt(sock_ssl, posix.IPPROTO.IPV6, std.os.linux.IPV6.V6ONLY, &std.mem.toBytes(@as(c_int, 0)));
                const address_ssl = try std.net.Address.parseIp6("::", config.ssl_port);
                try posix.bind(sock_ssl, &address_ssl.any, address_ssl.getOsSockLen());
                try posix.listen(sock_ssl, max_connections);
            }

            // Non-ssl socket
            const sock_non_ssl = try posix.socket(posix.AF.INET6, posix.SOCK.STREAM, 0);
            defer {
                posix.close(sock_non_ssl);
            }

            {
                errdefer {
                    std.log.err("Failed to setup non-SSL listener on port {}", .{config.non_ssl_port});
                }

                try posix.setsockopt(sock_non_ssl, posix.SOL.SOCKET, posix.SO.REUSEPORT, &std.mem.toBytes(@as(c_int, 1)));
                try posix.setsockopt(sock_non_ssl, posix.IPPROTO.IPV6, std.os.linux.IPV6.V6ONLY, &std.mem.toBytes(@as(c_int, 0)));
                const address_non_ssl = try std.net.Address.parseIp6("::", config.non_ssl_port);
                try posix.bind(sock_non_ssl, &address_non_ssl.any, address_non_ssl.getOsSockLen());
                try posix.listen(sock_non_ssl, max_connections);
            }

            std.log.info("Starting server at non-SSL port {}, SSL port {}", .{ config.non_ssl_port, config.ssl_port });

            // Start server
            if (!config.dry_run) {
                var threads: [config.thread_num]std.Thread = undefined;
                for (0..config.thread_num) |idx| {
                    const spawn_config = std.Thread.SpawnConfig{};
                    const thread = try std.Thread.spawn(spawn_config, run, .{
                        sock_ssl,
                        sock_non_ssl,
                        file_index_map.?,
                        file_storage.?,
                        key,
                        hostname,
                    });
                    threads[idx] = thread;
                }
                for (threads) |thread| {
                    std.Thread.join(thread);
                }
            }
            return 0;
        }
    } else {
        std.log.err(
            "Usage: {s} <hostname> <folder to serve> <certificate file> <certificate key file> \n e.g. example.org ~/public ~/keys/my_cert.cert ~/keys/my_key.key",
            .{executable},
        );
        return 1;
    }
}

const ThreadContext = struct {
    ring: *linux.IoUring,
    conns: *connections.Connections,
    file_index_map: files.FileIndexMap,
    file_storage: []const files.FileInfo,
    current_date: *?[]const u8,
    current_date_buf: []u8,
    hostname: []const u8,
};

fn run(
    sock_ssl: posix.fd_t,
    sock_non_ssl: posix.fd_t,
    file_index_map: files.FileIndexMap,
    file_storage: []const files.FileInfo,
    key: keys.Keys,
    hostname: []const u8,
) !void {
    var allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer {
        allocator.deinit();
    }

    var conns = try connections.Connections.init(allocator.allocator(), key);
    // don't defer deinit

    var ring: linux.IoUring = undefined;
    ring = try linux.IoUring.init(max_entries, linux.IORING_SETUP_SINGLE_ISSUER);
    defer {
        ring.deinit();
    }

    // var stdout = std.io.getStdOut();
    var cqes: [max_entries]linux.io_uring_cqe = undefined;

    var client_addr_ssl: net.Address = std.net.Address.initIp6(std.mem.zeroes([16]u8), 0, 0, 0);
    var client_addr_ssl_len: linux.socklen_t = client_addr_ssl.getOsSockLen();
    {
        const sqe = try ring.get_sqe();
        sqe.prep_accept(sock_ssl, &client_addr_ssl.any, &client_addr_ssl_len, 0);
        sqe.user_data = connections.encode(connections.IOOperation{ .accept = true });
        // Wait for the non ssl before ring submission
    }

    var client_addr_non_ssl: net.Address = std.net.Address.initIp6(std.mem.zeroes([16]u8), 0, 0, 0);
    var client_addr_non_ssl_len: linux.socklen_t = client_addr_ssl.getOsSockLen();
    {
        const sqe = try ring.get_sqe();
        sqe.prep_accept(sock_non_ssl, &client_addr_non_ssl.any, &client_addr_non_ssl_len, 0);
        sqe.user_data = connections.encode(connections.IOOperation{ .accept = false });
        _ = try ring.submit();
    }

    var current_date_buf: [128]u8 = undefined;
    var current_date: ?[]const u8 = null;

    const context = ThreadContext{
        .conns = &conns,
        .ring = &ring,
        .file_index_map = file_index_map,
        .file_storage = file_storage,
        .current_date_buf = &current_date_buf,
        .current_date = &current_date,
        .hostname = hostname,
    };

    while (true) {
        current_date = null;

        tracyMarkStart("loop");
        tracyMarkStart("submit-and-wait");
        // Batch submits and call them after the processing is done
        _ = try ring.submit_and_wait(1);
        tracyMarkEnd("submit-and-wait");

        tracyMarkStart("cqe");
        const copied_cqe_count = try ring.copy_cqes(&cqes, 1);
        tracyMarkEnd("cqe");
        if (copied_cqe_count <= 0) {
            std.log.err("Copied invalid count of cqes {}", .{copied_cqe_count});
            std.process.exit(1);
        } else if (copied_cqe_count > max_entries) {
            std.log.err("CQE overflow {}", .{copied_cqe_count});
            std.process.exit(1);
        }
        tracyMarkStart("cqe-loop");
        for (cqes[0..copied_cqe_count]) |cqe| {
            const op = connections.decode(cqe.user_data);
            switch (op) {
                connections.IOOperationType.accept => |is_ssl| {
                    std.log.debug("Event accept", .{});
                    tracyMarkStart("accept");
                    var accepted_sock: posix.fd_t = undefined;

                    if (cqe.res >= 0) {
                        accepted_sock = cqe.res;
                    } else {
                        std.log.err("Accept err: {}", .{cqe.err()});
                        std.process.exit(1);
                    }

                    const next_free_index = conns.nextFreeIndex();
                    if (next_free_index) |index| {
                        std.log.debug("Accept index: {}", .{index});
                        // setup new connection
                        conns.busy[index] = true;
                        conns.connections[index] = connections.Connection{
                            .socket = accepted_sock,
                            .is_ssl = is_ssl,
                        };
                        conns.busy_connections_count += 1;
                        conns.parsers[index].reset();

                        const result = ssl.br_ssl_server_reset(&conns.ssl_contexts[index]);
                        if (result != 1) {
                            const err = ssl.br_ssl_engine_last_error(&conns.ssl_contexts[index].eng);
                            std.log.err("BearSSL error: {}", .{err});
                            std.process.exit(1);
                        }

                        try posix.setsockopt(
                            accepted_sock,
                            posix.IPPROTO.TCP,
                            std.os.linux.TCP.NODELAY,
                            &std.mem.toBytes(@as(c_int, 1)),
                        );

                        // Prep read
                        if (is_ssl) {
                            const engine = &conns.ssl_contexts[index].eng;
                            try prepareReadSSL(&ring, &conns, index, engine);
                        } else {
                            try prepareReadNonSSL(&ring, &conns, index);
                        }
                    } else {
                        std.log.err("Exhausted free indices", .{});
                        std.process.exit(1);
                    }

                    {
                        // We need 1 free connection for ssl and 1 free for non-ssl
                        if (conns.busy_connections_count < max_connections - 1) {
                            // Prep another submit
                            const sqe = try ring.get_sqe();
                            const sock = if (is_ssl) sock_ssl else sock_non_ssl;
                            sqe.prep_accept(sock, null, null, 0);
                            sqe.user_data = connections.encode(.{ .accept = is_ssl });
                        } else {
                            if (is_ssl) {
                                conns.is_accept_ssl_bottlenecked = true;
                            } else {
                                conns.is_accept_non_ssl_bottlenecked = true;
                            }
                        }
                    }
                    tracyMarkEnd("accept");
                },
                connections.IOOperationType.read => |index| {
                    tracyMarkStart("read");
                    std.log.debug("Event read index: {}", .{index});
                    var bytes_read: usize = 0;
                    if (cqe.res < 0) {
                        const err = cqe.err();
                        switch (err) {
                            .CANCELED => {
                                std.log.debug("Canceled read, closing connection gracefully at {}", .{index});
                                try closeGracefully(index, context);
                                continue;
                            },
                            else => {
                                std.log.debug("Read error: {}", .{err});
                                try closeImmediately(index, &ring, &conns);
                                continue;
                            },
                        }
                    } else {
                        bytes_read = @intCast(cqe.res);
                    }
                    if (bytes_read > 0) {
                        std.log.debug("Bytes read: {}", .{bytes_read});
                        if (conns.connections[index].is_ssl) {
                            const engine = &conns.ssl_contexts[index].eng;
                            ssl.br_ssl_engine_recvrec_ack(engine, bytes_read);
                            try nextStepSSL(index, context);
                        } else {
                            conns.connections[index].non_ssl_read_bytes_pending = bytes_read;
                            try nextStepNonSSL(index, context);
                        }
                    } else {
                        try closeImmediately(index, &ring, &conns);
                    }
                    tracyMarkEnd("read");
                },
                connections.IOOperationType.write => |index| {
                    tracyMarkStart("write");
                    std.log.debug("Event write", .{});
                    if (cqe.res < 0) {
                        const err = cqe.err();
                        switch (err) {
                            .CANCELED => {
                                std.log.debug("Canceled write, closing connection at {}", .{index});
                                try closeImmediately(index, &ring, &conns);
                                continue;
                            },
                            else => {
                                std.log.debug("Write error: {}", .{err});
                                try closeImmediately(index, &ring, &conns);
                                continue;
                            },
                        }
                    } else if (cqe.res == 0) {
                        std.log.debug("Empty write", .{});
                        try closeImmediately(index, &ring, &conns);
                        continue;
                    }
                    if (cqe.res > 0) {
                        const bytes_written: usize = @intCast(cqe.res);
                        if (conns.connections[index].is_ssl) {
                            const engine = &conns.ssl_contexts[index].eng;
                            ssl.br_ssl_engine_sendrec_ack(engine, bytes_written);
                            try nextStepSSL(index, context);
                        } else {
                            const conn = &conns.connections[index];
                            conn.non_ssl_write_bytes_done += bytes_written;
                            if (conn.non_ssl_write_bytes_done == conn.non_ssl_write_bytes_pending) {
                                conn.non_ssl_write_bytes_pending = 0;
                                conn.non_ssl_write_bytes_done = 0;
                            } else if (conn.non_ssl_write_bytes_done > conn.non_ssl_write_bytes_pending) {
                                std.log.err("We wrote more bytes than were pending.", .{});
                                std.process.exit(1);
                            }
                            try nextStepNonSSL(index, context);
                        }
                    }
                    tracyMarkEnd("write");
                },
                connections.IOOperationType.close => |index| {
                    std.log.debug("Event close", .{});
                    if (conns.busy[index]) {
                        conns.busy_connections_count -= 1;
                        const is_ssl = conns.connections[index].is_ssl;
                        if (is_ssl and conns.is_accept_ssl_bottlenecked) {
                            conns.is_accept_ssl_bottlenecked = false;
                            const sqe = try ring.get_sqe();
                            sqe.prep_accept(sock_ssl, null, null, 0);
                            sqe.user_data = connections.encode(.{ .accept = true });
                        } else if (!is_ssl and conns.is_accept_non_ssl_bottlenecked) {
                            conns.is_accept_non_ssl_bottlenecked = false;
                            const sqe = try ring.get_sqe();
                            sqe.prep_accept(sock_non_ssl, null, null, 0);
                            sqe.user_data = connections.encode(.{ .accept = false });
                        }
                    }
                    conns.busy[index] = false;
                },
                connections.IOOperationType.timeout => {
                    if (cqe.res >= 0) {
                        std.log.debug("Got timeout", .{});
                    }
                },
            }
        }
        tracyMarkEnd("cqe-loop");
        tracyMarkEnd("loop");
    }

    return 0;
}

// Standard timeout
const timeout = linux.kernel_timespec{ .tv_sec = config.timeout_sec, .tv_nsec = 0 };

const WriteBufferResult = struct {
    bytes_written: usize,
    should_flush: bool,
};

fn writeResponseToBuffer(
    buf: []u8,
    index: usize,
    cmd_params: command.WriteDataCommand,
    context: ThreadContext,
) !WriteBufferResult {
    // Create date if we need one
    if (context.current_date.* == null) {
        const now = c.time(0);
        const tm = c.gmtime(&now).*;
        const date_bytes = c.strftime(
            context.current_date_buf.ptr,
            context.current_date_buf.len,
            "%a, %d %b %Y %H:%M:%S %Z",
            &tm,
        );
        if (date_bytes > 0) {
            context.current_date.* = context.current_date_buf[0..date_bytes];
        } else {
            std.log.err("Failed to get current date", .{});
            std.process.exit(1);
        }
    }

    var stream = std.io.fixedBufferStream(buf);
    var writer = stream.writer();

    const header_status = "HTTP/1.1 200 OK\r\n";
    const header_server = "Server: zzini-server\r\n";
    const header_date_format = "Date: {s}\r\n";
    const header_encoding = "Content-Encoding: gzip\r\n";
    const header_connection = "Connection: Keep-Alive\r\n";
    const header_keepalive = comptime std.fmt.comptimePrint(
        "Keep-Alive: timeout={}, max=1000\r\n",
        .{config.timeout_sec},
    );
    const header_cache = std.fmt.comptimePrint("Cache-Control: max-age={}\r\n", .{config.cache_max_age});
    const header_sts = "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\r\n";

    switch (cmd_params.data) {
        .file_idx => |file_idx| {
            const info = context.file_storage[file_idx];
            var bytes_written: usize = 0;
            // We assume there's space for at least a header
            if (!cmd_params.was_status_written) {
                _ = try writer.write(header_status);
            }
            if (!cmd_params.was_header_written) {
                _ = try writer.write(header_server);
                _ = try std.fmt.format(writer, header_date_format, .{context.current_date.*.?});
                _ = try writer.write(header_connection);
                _ = try writer.write(header_keepalive);
                _ = try writer.write(header_cache);
                if (!config.allow_insecure_http) {
                    _ = try writer.write(header_sts);
                }
                if (info.is_compressed) {
                    _ = try writer.write(header_encoding);
                }
                _ = try std.fmt.format(writer, "Content-Type: {s}\r\n", .{info.mime});
                _ = try std.fmt.format(writer, "Content-Length: {}\r\n", .{info.data.len});
                if (cmd_params.should_add_etag) {
                    _ = try std.fmt.format(writer, "ETag: {s}\r\n", .{info.hash});
                }
                _ = try writer.write("\r\n");
                bytes_written = try stream.getPos();
            }
            var bytes_written_output: usize = undefined;
            if (!cmd_params.is_head_method) {
                const capacity_left = buf.len - bytes_written;
                const len_to_read = info.data.len - cmd_params.file_bytes_written;
                const len_to_write = @min(capacity_left, len_to_read);
                @memcpy(
                    buf[bytes_written .. bytes_written + len_to_write],
                    info.data[cmd_params.file_bytes_written .. cmd_params.file_bytes_written + len_to_write],
                );
                bytes_written_output = bytes_written + len_to_write;
                if (len_to_write < len_to_read) {
                    std.log.debug("Index {} smaller write", .{index});
                    context.conns.connections[index].writer_state = .{
                        .index = index,
                        .data = .{ .file_idx = file_idx },
                        .was_status_written = true,
                        .was_header_written = true,
                        .file_bytes_written = cmd_params.file_bytes_written + len_to_write,
                    };
                } else {
                    context.conns.connections[index].writer_state = null;
                }
            } else {
                bytes_written_output = bytes_written;
                context.conns.connections[index].writer_state = null;
            }
            return .{ .bytes_written = bytes_written_output, .should_flush = true };
        },
        .err => |err| {
            _ = try writer.write(err.statusLine());
            if (err.fileName()) |filename| {
                const file_idx = context.file_index_map.get(filename).?;
                context.conns.connections[index].writer_state = .{
                    .index = index,
                    .data = .{ .file_idx = file_idx },
                    .was_status_written = true,
                    .was_header_written = false,
                    .file_bytes_written = 0,
                    .should_add_etag = false,
                    .is_head_method = cmd_params.is_head_method,
                };
                return .{ .bytes_written = try stream.getPos(), .should_flush = false };
            } else {
                _ = try writer.write(header_server);
                if (!config.allow_insecure_http) {
                    _ = try writer.write(header_sts);
                }
                _ = try std.fmt.format(writer, header_date_format, .{context.current_date.*.?});
                // Cache hit doesn't return content length
                if (err.isCacheHit()) {
                    _ = try writer.write(header_cache);
                } else {
                    _ = try writer.write("Content-Length: 0\r\n");
                }
                _ = try writer.write("\r\n");
                context.conns.connections[index].writer_state = null;
                return .{ .bytes_written = try stream.getPos(), .should_flush = true };
            }
        },
        .ssl_redirect => |path| {
            const status_line = "HTTP/1.1 301 Moved Permanently\r\n";
            _ = try writer.write(status_line);
            _ = try writer.write(header_server);
            if (!config.allow_insecure_http) {
                _ = try writer.write(header_sts);
            }
            _ = try std.fmt.format(writer, header_date_format, .{context.current_date.*.?});
            _ = try writer.write("Content-Length: 0\r\n");
            // SSL Redirect needs a location
            _ = try std.fmt.format(writer, "Location: https://{s}:{}{s}\r\n", .{ context.hostname, config.ssl_port, path });
            _ = try writer.write("\r\n");
            context.conns.connections[index].writer_state = null;
            return .{ .bytes_written = try stream.getPos(), .should_flush = true };
        },
    }
}

fn closeGracefully(
    index: usize,
    context: ThreadContext,
) !void {
    tracyMarkStart("close");
    defer {
        tracyMarkEnd("close");
    }
    const conns = context.conns;
    if (conns.connections[index].is_ssl and !conns.connections[index].is_closing_gracefully) {
        conns.connections[index].is_closing_gracefully = true;
        const engine = &conns.ssl_contexts[index].eng;
        ssl.br_ssl_engine_close(engine);
        try nextStepSSL(index, context);
    } else {
        try prepareClose(context.ring, conns, index);
    }
}

fn closeImmediately(index: usize, ring: *linux.IoUring, conns: *connections.Connections) !void {
    const engine = &conns.ssl_contexts[index].eng;
    ssl.br_ssl_engine_close(engine);
    try prepareClose(ring, conns, index);
}

fn prepareReadSSL(ring: *linux.IoUring, conns: *connections.Connections, index: usize, engine: *ssl.br_ssl_engine_context) !void {
    var capacity_available: usize = undefined;
    const buf = ssl.br_ssl_engine_recvrec_buf(engine, &capacity_available);
    if (capacity_available == 0) {
        unreachable;
    }
    const sqe = try ring.get_sqe();
    sqe.prep_read(conns.connections[index].socket, buf[0..capacity_available], 0);
    sqe.user_data = connections.encode(.{ .read = index });
    sqe.flags |= linux.IOSQE_IO_LINK;
    _ = try ring.link_timeout(connections.encode(connections.IOOperation.timeout), &timeout, 0);
}

fn prepareReadNonSSL(ring: *linux.IoUring, conns: *connections.Connections, index: usize) !void {
    const capacity_available = conns.ssl_buffers[index].len;
    const buf = conns.ssl_buffers[index];
    if (capacity_available == 0) {
        unreachable;
    }
    const sqe = try ring.get_sqe();
    sqe.prep_read(conns.connections[index].socket, buf[0..capacity_available], 0);
    sqe.user_data = connections.encode(.{ .read = index });
    sqe.flags |= linux.IOSQE_IO_LINK;
    _ = try ring.link_timeout(connections.encode(connections.IOOperation.timeout), &timeout, 0);
}

fn prepareWriteSSL(ring: *linux.IoUring, conns: *connections.Connections, index: usize, engine: *ssl.br_ssl_engine_context) !void {
    var capacity_available: usize = undefined;
    const buf = ssl.br_ssl_engine_sendrec_buf(engine, &capacity_available);
    if (capacity_available == 0) {
        unreachable;
    }
    const sqe = try ring.get_sqe();
    std.log.debug("Writing {} bytes", .{capacity_available});
    sqe.prep_write(conns.connections[index].socket, buf[0..capacity_available], 0);
    sqe.user_data = connections.encode(.{ .write = index });
    sqe.flags |= linux.IOSQE_IO_LINK;
    _ = try ring.link_timeout(connections.encode(connections.IOOperation.timeout), &timeout, 0);
}

fn prepareWriteNonSSL(ring: *linux.IoUring, conns: *connections.Connections, index: usize) !void {
    const buf = conns.ssl_buffers[index];
    const start_bytes = conns.connections[index].non_ssl_write_bytes_done;
    const end_bytes = conns.connections[index].non_ssl_write_bytes_pending;
    if (end_bytes == 0) {
        unreachable;
    }
    const sqe = try ring.get_sqe();
    std.log.debug("Writing {} bytes", .{end_bytes});
    sqe.prep_write(conns.connections[index].socket, buf[start_bytes..end_bytes], 0);
    sqe.user_data = connections.encode(.{ .write = index });
    sqe.flags |= linux.IOSQE_IO_LINK;
    _ = try ring.link_timeout(connections.encode(connections.IOOperation.timeout), &timeout, 0);
}

fn prepareClose(ring: *linux.IoUring, conns: *connections.Connections, index: usize) !void {
    tracyMarkStart("close");
    defer {
        tracyMarkEnd("close");
    }
    if (!conns.connections[index].is_closing) {
        conns.connections[index].is_closing = true;
        const sqe = try ring.get_sqe();
        sqe.prep_close(conns.connections[index].socket);
        sqe.user_data = connections.encode(.{ .close = index });
    }
}

// Returns whether the opration was successful
// False means close the connection
// Error means unrecoverable error
fn processRecvApp(
    index: usize,
    engine: *ssl.br_ssl_engine_context,
    context: ThreadContext,
) !bool {
    var data_len: usize = undefined;
    const buf = ssl.br_ssl_engine_recvapp_buf(engine, &data_len);
    // Read data
    var parse = &context.conns.parsers[index];
    const possible_result = parse.parse(buf[0..data_len]);
    ssl.br_ssl_engine_recvapp_ack(engine, data_len);
    return processParsingOutput(
        index,
        data_len,
        possible_result,
        context,
    );
}

// If return value is false, we must close the connection
fn processParsingOutput(
    index: usize,
    data_len: usize,
    bytes_read: parser.Error!usize,
    context: ThreadContext,
) bool {
    var parse = &context.conns.parsers[index];
    var connection = &context.conns.connections[index];
    if (bytes_read) |result| {
        if (parse.state.parsing_done) {
            if (result < data_len) {
                // We do not support pipelining
                return false;
            } else {
                const is_head = parse.state.method == .head;
                if (!config.allow_insecure_http and !context.conns.connections[index].is_ssl) {
                    const path = parse.path_buf[0..parse.state.path_len];
                    connection.writer_state = .{
                        .index = index,
                        .data = .{ .ssl_redirect = path },
                        .is_head_method = is_head,
                    };
                } else if (files.getFileIndex(context.file_index_map, parse.path_buf, &parse.state.path_len)) |file_idx| {
                    std.log.debug("File index: {}", .{file_idx});
                    const etag = context.file_storage[file_idx].hash;
                    const parsed_etag = parse.etag_buf[0..parse.state.etag_len];
                    var cache_hit = false;
                    if (parsed_etag.len == 1 and parsed_etag[0] == '*') {
                        cache_hit = true;
                    } else if (parsed_etag.len >= etag.len) {
                        // This checks for sequences of etags e.g. abc, cbd
                        // Also helps in case browser sends W/ + etag
                        for (0..(parsed_etag.len - etag.len + 1)) |start| {
                            if (std.mem.eql(u8, parsed_etag[start .. start + etag.len], etag)) {
                                cache_hit = true;
                                break;
                            }
                        }
                    }

                    if (cache_hit) {
                        connection.writer_state = .{
                            .index = index,
                            .data = .{ .err = .cache_hit },
                        };
                    } else {
                        connection.writer_state = .{
                            .index = index,
                            .data = .{
                                .file_idx = file_idx,
                            },
                            .is_head_method = is_head,
                        };
                    }
                } else |_| {
                    connection.writer_state = .{
                        .index = index,
                        .data = .{
                            .err = .not_found,
                        },
                        .is_head_method = is_head,
                    };
                }
                // Prepare for the next request
                parse.reset();
                return true;
            }
        } else {
            return true;
        }
    } else |err| {
        std.log.debug("Parsing error {}", .{err});
        if (err == parser.Error.drained) {
            if (parse.state.content_error) |content_error| {
                switch (content_error) {
                    parser.ContentError.path_too_long => {
                        connection.writer_state = .{
                            .index = index,
                            .data = .{
                                .err = .not_found,
                            },
                        };
                    },
                    parser.ContentError.unsupported_method => {
                        connection.writer_state = .{
                            .index = index,
                            .data = .{
                                .err = .unsupported_method,
                            },
                        };
                    },
                    else => {
                        return false;
                    },
                }
            } else {
                // We always set content error before going into drained state
                unreachable;
            }
            // Prepare for the next request
            parse.reset();
            return true;
        } else {
            // Malformed request, no need to keep the connection
            return false;
        }
    }
}

fn processSendApp(
    index: usize,
    context: ThreadContext,
    engine: *ssl.br_ssl_engine_context,
    writer_state: command.WriteDataCommand,
) !void {
    var capacity: usize = undefined;
    const buf = ssl.br_ssl_engine_sendapp_buf(engine, &capacity);
    const result = try writeResponseToBuffer(
        buf[0..capacity],
        index,
        writer_state,
        context,
    );
    ssl.br_ssl_engine_sendapp_ack(engine, result.bytes_written);
    if (result.should_flush) {
        ssl.br_ssl_engine_flush(engine, 0);
    }
}

// Checks the current status of things and proceeds based on the state
// Should be called if and only if there are no other outstanding tasks
fn nextStepSSL(
    index: usize,
    context: ThreadContext,
) !void {
    var repeat = true;
    var close = false;
    while (repeat) {
        repeat = false;
        const conn = &context.conns.connections[index];
        const engine = &context.conns.ssl_contexts[index].eng;
        const state = ssl.br_ssl_engine_current_state(engine);
        if (state == ssl.BR_SSL_CLOSED) {
            std.log.debug("Index {} engine is closed", .{index});
            close = true;
        } else if ((state & ssl.BR_SSL_SENDREC) > 0) {
            try prepareWriteSSL(context.ring, context.conns, index, engine);
        } else if ((state & ssl.BR_SSL_RECVAPP) > 0) {
            if (conn.writer_state != null) {
                // We are writing, not reading, that means we've received too much data from client
                close = true;
            } else {
                const success = try processRecvApp(index, engine, context);
                if (!success) {
                    close = true;
                } else {
                    repeat = true;
                }
            }
        } else if ((state & ssl.BR_SSL_SENDAPP) > 0 and conn.writer_state != null) {
            const writer_state = conn.writer_state.?;
            try processSendApp(
                index,
                context,
                engine,
                writer_state,
            );
            repeat = true;
        } else if ((state & ssl.BR_SSL_RECVREC) > 0) {
            if (conn.writer_state != null) {
                std.log.err("Invalid state RECVREC with writer state {?}", .{conn.writer_state});
                std.process.exit(1);
            } else {
                try prepareReadSSL(context.ring, context.conns, index, engine);
            }
        }
    }
    if (close) {
        try prepareClose(context.ring, context.conns, index);
    }
}

fn nextStepNonSSL(
    index: usize,
    context: ThreadContext,
) !void {
    var repeat = true;
    var close = false;

    const conn = &context.conns.connections[index];
    while (repeat) {
        repeat = false;
        if (conn.writer_state) |writer_state| {
            if (conn.non_ssl_read_bytes_pending > 0) {
                // We have extra data
                close = true;
            } else {
                const buf = context.conns.ssl_buffers[index];
                const result = try writeResponseToBuffer(
                    buf,
                    index,
                    writer_state,
                    context,
                );
                conn.non_ssl_write_bytes_pending += result.bytes_written;
                if (result.should_flush) {
                    try prepareWriteNonSSL(context.ring, context.conns, index);
                } else {
                    repeat = true;
                }
            }
        } else {
            if (conn.non_ssl_write_bytes_pending > 0) {
                try prepareWriteNonSSL(context.ring, context.conns, index);
            } else if (conn.non_ssl_read_bytes_pending == 0) {
                try prepareReadNonSSL(context.ring, context.conns, index);
            } else {
                var buf = context.conns.ssl_buffers[index];
                var parse = &context.conns.parsers[index];
                const data_len = conn.non_ssl_read_bytes_pending;
                const possible_result = parse.parse(buf[0..data_len]);
                conn.non_ssl_read_bytes_pending = 0;
                const success = processParsingOutput(
                    index,
                    data_len,
                    possible_result,
                    context,
                );
                if (success) {
                    repeat = true;
                } else {
                    close = true;
                }
            }
        }
    }
    if (close) {
        try prepareClose(context.ring, context.conns, index);
    }
}
