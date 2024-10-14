// How many bits are used to index a connection
// Max number of connections would be 2 ** bits
pub const index_bits: u5 = 10;

// Timeout for read requests
pub const timeout_sec = 30;

// Http cache in sec, used for Cache-Control header
pub const cache_max_age = 3600;

// Max size of a single compressed size (after compression, doesn't apply to images etc)
pub const max_compressed_file_size: usize = 64 * 1024 * 1024;

// Total size for all files. If served folder exceeds this value, the server won't start
pub const total_cache_size: usize = 256 * 1024 * 1024;

// Port for non SSL socket
pub const non_ssl_port = 80;

// Port for SSL socket
pub const ssl_port = 443;

// If false, http requests will be redirected to https endpoint
pub const allow_insecure_http = false;

// How many threads to use to serve requests
// Special value 0 means equal to cpu cores
pub const thread_num = 0;

// Do not start server
pub const dry_run = false;
