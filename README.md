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

# Benchmarks

Here are some lazy benchmarks on my machine on a single thread against localhost (on 9090 and 9091 ports + allow insecure http, changeable in the config)
Built with `zig build --release=fast`

- HTTP

`oha -z10s -c 1024 http://localhost:9090 `

```
Summary:
  Success rate: 100.00%
  Total:        16.7562 secs
  Slowest:      1.4976 secs
  Fastest:      0.0001 secs
  Average:      0.0064 secs
  Requests/sec: 157766.0325

  Total data:   327.74 MiB
  Size/request: 130 B
  Size/sec:     19.56 MiB

Response time histogram:
  0.000 [1]       |
  0.150 [2642933] |■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  0.300 [102]     |
  0.449 [115]     |
  0.599 [79]      |
  0.749 [70]      |
  0.899 [67]      |
  1.048 [56]      |
  1.198 [55]      |
  1.348 [49]      |
  1.498 [28]      |
```

- HTTPS with reuse (2048 RSA key)

`oha -z10s --insecure -c 1024 https://localhost:9091`

```
Summary:
  Success rate: 100.00%
  Total:        5.4975 secs
  Slowest:      2.0863 secs
  Fastest:      0.0001 secs
  Average:      0.0121 secs
  Requests/sec: 82611.9244

  Total data:   56.31 MiB
  Size/request: 130 B
  Size/sec:     10.24 MiB

Response time histogram:
  0.000 [1]      |
  0.209 [453135] |■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  0.417 [0]      |
  0.626 [0]      |
  0.835 [0]      |
  1.043 [0]      |
  1.252 [0]      |
  1.460 [0]      |
  1.669 [0]      |
  1.878 [0]      |
  2.086 [1023]   |
```

- HTTPS without reuse (2048 RSA key)

`oha -z10s --insecure -c 1024 https://localhost:9091 --disable-keepalive`

```
Summary:
  Success rate: 100.00%
  Total:        10.0221 secs
  Slowest:      2.1511 secs
  Fastest:      0.1397 secs
  Average:      1.6962 secs
  Requests/sec: 642.3809

  Total data:   688.09 KiB
  Size/request: 130 B
  Size/sec:     68.66 KiB

Response time histogram:
  0.140 [1]    |
  0.341 [131]  |■
  0.542 [116]  |
  0.743 [114]  |
  0.944 [114]  |
  1.145 [115]  |
  1.347 [114]  |
  1.548 [117]  |
  1.749 [132]  |■
  1.950 [4133] |■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  2.151 [333]  |■■
```

