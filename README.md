# Summary

A simple static HTTP 1.1 + TLS 1.2 server that loads all files into ram before serving

## Disclaimer

This is a toy project, I have no idea what I'm doing. **Do not use in production**

## Purpose

This server uses Linux io_uring + BearSSL. It is reasonably fast and has predictable memory usage. While the server is running, it is _mostly_ not allocating memory dynamically

# Building

0. Take a look at `src/config.zig` for any parameters to adjust
1. Get BearSSL from https://bearssl.org/
2. Compile the BearSSL static lib. Put it into `lib/` folder
3. BearSSL includes go into `include/bearssl/` folder
4. This currently compiles with Zig 0.13. I would recommend using `zig build --release=safe` due to the fact that it preserves boundary checks
5. Compiled binary is located at `zig-out/bin` folder

# Running

1. Due to io_uring, this server requires Linux with a recent kernel. I have tested it on Ubuntu Server 24.04 LTS
2. You would need to adjust `nofile` limits to exceed the number of concurrent connections in the config
3. This server is recommended to run as a regular user (not root). This means the html folder and key files must be readable by that user.
4. To run the binary, you need to provide 4 arguments: hostname, html folder to serve, certificate pem file, certificate key file. E.g. `/usr/local/bin/zzini-server localhost public/ /my/cert.pem /my/key.pem`
5. For testing purposes, you can generate self-signed keys using OpenSSL

# Misc
- The server doesn't monitor files. Any changes require a server restart
- This isn't server really HTTP/1.1 compliant because it serves only gzipped files (among other issues). This should work with modern browsers though.
- I have added an example systemd service config as an illustration
- For now, the server supports only ED25519 and RSA keys
- This server should work with Certbot Lets Encrypt SSL keys, but because of the non-root user it requires fiddling with `chown` and `post-hooks` 
- It is possible to compile this with Tracy debugger support, but it's not necessary.
- The main reason for this project for me was to learn Zig and io_uring
