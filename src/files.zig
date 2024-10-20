const std = @import("std");
const config = @import("config.zig");

pub const FileDataType = enum(u1) {
    memory,
    filesystem,
};

pub const FileData = union(FileDataType) {
    // Memory contains file contents
    memory: []const u8,
    // File system contains file path
    filesystem: []const u8,
};

pub const FileInfo = struct {
    data: FileData,
    hash: []const u8,
    mime: []const u8,
    is_compressed: bool,
    len: usize,
};

pub const FileIndexMap = std.StringHashMap(usize);

pub const LoadFilesResult = struct {
    buffer: []u8,
    file_index_map: FileIndexMap,
    file_storage: []const FileInfo,
};

const FileEntry = struct {
    name: []const u8,
    kind: std.fs.Dir.Entry.Kind,
    parent_path: []const u8,
    http_path: []const u8,
};

pub const FileError = error{
    cache_overflow,
};

// Passed in allocator will be used to allocate buffers like hashes and file contents
// Returns slice and file_storage. Caller owns slice memory
pub fn loadFiles(external_allocator: std.mem.Allocator, filename: []const u8) !LoadFilesResult {
    errdefer {
        std.log.err("Failed to load files at path {s}", .{filename});
    }

    const fixed_buffer = try external_allocator.alloc(u8, config.total_cache_size);
    var fixed_allocator = std.heap.FixedBufferAllocator.init(fixed_buffer);
    const output_allocator = fixed_allocator.allocator();
    // Poor man's garbage collection
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer {
        arena.deinit();
    }
    var arena_allocator = arena.allocator();

    var file_index_map = FileIndexMap.init(arena_allocator);
    var array_file_storage = std.ArrayList(FileInfo).init(arena_allocator);

    const file_cache_buffer = try arena_allocator.alloc(u8, config.max_compressed_file_size);

    var exec_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer {
        exec_arena.deinit();
    }
    const exec_arena_allocator = exec_arena.allocator();

    const time: i64 = std.time.milliTimestamp();
    if (time < 0) {
        std.log.err("Negative time\n", .{});
        unreachable;
    }
    const seed: u64 = 0; // Keep hashes consistent

    {
        var file_stack = std.ArrayList(FileEntry).init(arena_allocator);
        try file_stack.append(.{
            .name = filename,
            .kind = .directory,
            .parent_path = "",
            .http_path = "/",
        });

        {
            while (file_stack.items.len > 0) {
                const item = file_stack.pop();

                switch (item.kind) {
                    .file => {
                        var parent_folder = try std.fs.cwd().openDir(item.parent_path, .{});
                        defer {
                            parent_folder.close();
                        }
                        const file_handle = try parent_folder.openFile(item.name, .{});
                        defer {
                            file_handle.close();
                        }
                        const file_reader = file_handle.reader();
                        const file_result = try std.process.Child.run(.{
                            .allocator = exec_arena_allocator,
                            .argv = &[_][]const u8{ "/usr/bin/file", "-b", "-i", item.name },
                            .cwd = null,
                            .cwd_dir = parent_folder,
                        });
                        if (file_result.stdout.len == 0) {
                            std.log.err("Couldn't determine mime-type for {s}", .{item.name});
                            _ = exec_arena.reset(.{ .retain_capacity = {} });
                            continue;
                        }
                        // We need to remove trailing newline
                        const mime = try output_allocator.dupe(u8, file_result.stdout[0 .. file_result.stdout.len - 1]);
                        _ = exec_arena.reset(.{ .retain_capacity = {} });
                        const binary_postfix = "binary";
                        const should_compress =
                            (mime.len < binary_postfix.len or !std.mem.eql(u8, binary_postfix, mime[mime.len - binary_postfix.len .. mime.len]));
                        var file_data_storage: []u8 = undefined;
                        if (should_compress) {
                            var file_cache_data_stream = std.io.fixedBufferStream(file_cache_buffer);
                            const file_cache_data_writer = file_cache_data_stream.writer();
                            try std.compress.gzip.compress(file_reader, file_cache_data_writer, .{});
                            const data_written = file_cache_data_stream.getWritten();
                            if (data_written.len == file_cache_buffer.len) {
                                std.log.err("File {s} exceeded max_size {}", .{ item.name, file_cache_buffer.len });
                                continue;
                            }
                            file_data_storage = try output_allocator.dupe(u8, data_written);
                        } else {
                            const bytes_written = try file_reader.readAll(file_cache_buffer);
                            if (bytes_written == file_cache_buffer.len) {
                                std.log.err("File {s} exceeded max_size {}", .{ item.name, file_cache_buffer.len });
                                continue;
                            }
                            file_data_storage = try output_allocator.dupe(u8, file_cache_buffer[0..bytes_written]);
                        }
                        const hash = std.hash.XxHash64.hash(seed, file_data_storage);
                        const hash_size = comptime std.base64.standard.Encoder.calcSize(8);
                        const encoded_hash = try output_allocator.alloc(u8, hash_size);
                        _ = std.base64.standard.Encoder.encode(encoded_hash, &std.mem.toBytes(hash));
                        const http_path = try output_allocator.dupe(u8, item.http_path);
                        std.log.debug("File name {s} http path {s}", .{ item.name, item.http_path });
                        const file_info = FileInfo{
                            .data = .{ .memory = file_data_storage },
                            .hash = encoded_hash,
                            .mime = mime,
                            .is_compressed = should_compress,
                            .len = file_data_storage.len,
                        };
                        try array_file_storage.append(file_info);
                        try file_index_map.put(http_path, array_file_storage.items.len - 1);
                    },
                    .directory => {
                        var should_close = false;
                        var parent_folder: std.fs.Dir = undefined;
                        if (item.parent_path.len > 0) {
                            parent_folder = try std.fs.cwd().openDir(item.parent_path, .{});
                            should_close = true;
                        } else {
                            parent_folder = std.fs.cwd();
                        }
                        defer {
                            if (should_close) {
                                parent_folder.close();
                            }
                        }
                        var file_list = try parent_folder.openDir(item.name, .{ .iterate = true });
                        defer {
                            file_list.close();
                        }

                        var files_iterator = file_list.iterate();
                        const new_parent_path = blk: {
                            var realpath_buffer: [std.fs.max_path_bytes]u8 = undefined;
                            const realpath = try parent_folder.realpath(item.name, &realpath_buffer);
                            break :blk try arena_allocator.dupe(u8, realpath);
                        };
                        while (try files_iterator.next()) |file| {
                            var new_http_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
                            var new_http_path_stream = std.io.fixedBufferStream(&new_http_path_buffer);
                            switch (file.kind) {
                                .file => {
                                    try std.fmt.format(new_http_path_stream.writer(), "{s}{s}", .{ item.http_path, file.name });
                                },
                                .directory => {
                                    // Directories are not added to the file storage, the http path here is used as a component
                                    try std.fmt.format(new_http_path_stream.writer(), "{s}{s}/", .{ item.http_path, file.name });
                                },
                                else => {
                                    // Unsupported
                                },
                            }
                            try file_stack.append(.{
                                .name = try arena_allocator.dupe(u8, file.name),
                                .kind = file.kind,
                                .parent_path = new_parent_path,
                                .http_path = try arena_allocator.dupe(u8, new_http_path_stream.getWritten()),
                            });
                        }
                    },
                    else => {
                        // Unsupported
                    },
                }
            }
        }
    }

    const duped_file_index_map = try file_index_map.cloneWithAllocator(output_allocator);
    const duped_array_file_storage = try output_allocator.dupe(FileInfo, array_file_storage.items);

    _ = external_allocator.resize(fixed_buffer, fixed_allocator.end_index);
    return .{
        .buffer = fixed_buffer[0..fixed_allocator.end_index],
        .file_index_map = duped_file_index_map,
        .file_storage = duped_array_file_storage,
    };
}

pub const PathError = error{no_file};

const FixupStep = enum { remove_trailing_slash, add_extension, add_index_html };

// Accepts a path from the request, throws if it couldn't fix it up
// This function does simple transformations like adding index.html to driectories and such
pub fn getFileIndex(storage: FileIndexMap, path_buffer: []u8, path_len: *usize) !usize {
    const raw_path = path_buffer[0..path_len.*];
    const error_prefix = "/_error";
    // Attempting to read _error will always result in 404
    if (raw_path.len >= error_prefix.len and std.mem.eql(u8, raw_path[0..error_prefix.len], error_prefix)) {
        return PathError.no_file;
    }

    if (storage.get(raw_path)) |idx| {
        // We are done, no need to fixup
        return idx;
    }
    // For each fixup, we try a fixup, if this works we return
    // Otherwise, we return the path to the original state and try the next fixup
    var next_fixup_step: ?FixupStep = .add_index_html;
    while (next_fixup_step) |fixup_step| {
        switch (fixup_step) {
            .add_index_html => {
                const suffix: []const u8 =
                    if (path_len.* > 0 and path_buffer[path_len.* - 1] == '/')
                    "index.html"
                else
                    "/index.html";
                if (path_len.* < path_buffer.len - suffix.len) {
                    @memcpy(path_buffer[path_len.* .. path_len.* + suffix.len], suffix);
                    path_len.* += suffix.len;
                    if (storage.get(path_buffer[0..path_len.*])) |idx| {
                        return idx;
                    }
                    path_len.* -= suffix.len;
                }
                next_fixup_step = .add_extension;
            },
            .add_extension => {
                const suffix = ".html";
                if (path_len.* < path_buffer.len - suffix.len) {
                    @memcpy(path_buffer[path_len.* .. path_len.* + suffix.len], suffix);
                    path_len.* += suffix.len;
                    if (storage.get(path_buffer[0..path_len.*])) |idx| {
                        return idx;
                    }
                    path_len.* -= suffix.len;
                }
                next_fixup_step = .remove_trailing_slash;
            },
            .remove_trailing_slash => {
                if (path_len.* > 0 and path_buffer[path_len.* - 1] == '/') {
                    path_len.* -= 1;
                    if (storage.get(path_buffer[0..path_len.*])) |idx| {
                        return idx;
                    }
                    path_len.* += 1;
                }
                next_fixup_step = null;
            },
        }
    }
    // We couldn't fix the path up
    return PathError.no_file;
}
