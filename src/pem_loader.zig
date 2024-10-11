const std = @import("std");
const connections = @import("connections.zig");
const ssl = connections.ssl;

const BufferWithPos = struct {
    buffer: []u8,
    pos: usize,
};

const BufferSlice = struct {
    buffers: []BufferWithPos,
    current_idx: usize,
};

const PemError = error{ multiobject_not_supported, failed_to_parse };

pub fn read_pem(allocator: std.mem.Allocator, filename: []const u8) ![][]u8 {
    // We should provide some reasonable amount of storage to decode the certificate
    const max_bytes = 1024 * 32;
    const max_certificates = 10;

    const file_bytes = try std.fs.cwd().readFileAlloc(allocator, filename, max_bytes * max_certificates);
    defer {
        allocator.free(file_bytes);
    }

    var br_context: ssl.br_pem_decoder_context = undefined;
    ssl.br_pem_decoder_init(&br_context);

    var cert_writers_array: [max_certificates]BufferWithPos = undefined;
    for (0..max_certificates) |i| {
        const cert_buffer = try allocator.alloc(u8, max_bytes);
        cert_writers_array[i] = BufferWithPos{ .buffer = cert_buffer, .pos = 0 };
    }
    var cert_writers = BufferSlice{ .buffers = &cert_writers_array, .current_idx = 0 };

    ssl.br_pem_decoder_setdest(&br_context, &pem_receive_bytes, @ptrCast(&cert_writers));
    var total_bytes_read: usize = 0;
    var read_bytes = ssl.br_pem_decoder_push(&br_context, file_bytes.ptr, file_bytes.len);
    total_bytes_read += read_bytes;
    var last_event: i32 = -1;
    while (total_bytes_read < file_bytes.len) {
        read_bytes = ssl.br_pem_decoder_push(
            &br_context,
            file_bytes[total_bytes_read..file_bytes.len].ptr,
            file_bytes.len - total_bytes_read,
        );
        if (read_bytes == 0) {
            last_event = ssl.br_pem_decoder_event(&br_context);
            if (last_event == ssl.BR_PEM_END_OBJ) {
                cert_writers.current_idx += 1;
            }
        }
        total_bytes_read += read_bytes;
    }

    last_event = ssl.br_pem_decoder_event(&br_context);
    if (last_event == ssl.BR_PEM_END_OBJ) {
        cert_writers.current_idx += 1;
    }

    if (cert_writers.current_idx == 0) {
        std.log.err("Failed to parse public key {}", .{last_event});
        for (cert_writers.buffers) |writer| {
            allocator.free(writer.buffer);
        }
        return PemError.failed_to_parse;
    } else {
        var return_slices = try allocator.alloc([]u8, cert_writers.current_idx);
        for (0..cert_writers.current_idx) |i| {
            return_slices[i] = cert_writers.buffers[i].buffer[0..cert_writers.buffers[i].pos];
            _ = allocator.resize(cert_writers.buffers[i].buffer, return_slices[i].len);
        }
        // Clean up unused buffers
        for (cert_writers.current_idx..cert_writers.buffers.len) |i| {
            allocator.free(cert_writers.buffers[i].buffer);
        }
        return return_slices;
    }
}

// Receives a writer as context
fn pem_receive_bytes(dest_ctx: ?*anyopaque, src: ?*const anyopaque, src_len: usize) callconv(.C) void {
    const writers: *BufferSlice = @ptrCast(@alignCast(dest_ctx));
    if (writers.current_idx >= writers.buffers.len) {
        std.log.err("Exceeded max certs {}", .{writers.buffers.len});
        std.process.exit(1);
    }
    var writer = &writers.buffers[writers.current_idx];
    if (writer.pos + src_len > writer.buffer.len) {
        std.log.err("Buffer overflow when reading pem file", .{});
        std.process.exit(1);
    }
    @memcpy(writer.buffer[writer.pos .. writer.pos + src_len], @as([*]u8, @ptrCast(@constCast(src)))[0..src_len]);
    writer.pos += src_len;
}
