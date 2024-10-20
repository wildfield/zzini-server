// How many bits are used to index a connection
// Max number of connections would be 2 ** bits
pub const index_bits: u5 = 10;

// Timeout for read requests
pub const timeout_sec = 30;

// Http cache in sec, used for Cache-Control header
pub const cache_max_age = 3600;

// Max size of a single compressed size (after compression, doesn't apply to images etc)
pub const max_compressed_file_size: usize = 8 * 1024 * 1024;

// Total size for compressed files. If compressed files exceed this value, the server won't start
// Compressible files are determined by checking whether charset is binary
pub const total_cache_size: usize = 128 * 1024 * 1024;

// Port for non SSL socket
pub const non_ssl_port = 9090;

// Port for SSL socket
pub const ssl_port = 9091;

// If false, http requests will be redirected to https endpoint
pub const allow_insecure_http = false;

// How many threads to use to serve requests
// Special value 0 means equal to cpu cores
pub const thread_num = 0;

// Do not start server
pub const dry_run = false;
