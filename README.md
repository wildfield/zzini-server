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
  Total:        10.0064 secs
  Slowest:      0.8829 secs
  Fastest:      0.0000 secs
  Average:      0.0061 secs
  Requests/sec: 166763.8429

  Total data:   206.81 MiB
  Size/request: 130 B
  Size/sec:     20.67 MiB

Response time histogram:
  0.000 [1]       |
  0.088 [1667679] |■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  0.177 [197]     |
  0.265 [36]      |
  0.353 [38]      |
  0.441 [35]      |
  0.530 [34]      |
  0.618 [33]      |
  0.706 [34]      |
  0.795 [34]      |
  0.883 [30]      |
```

- HTTPS with reuse (2048 RSA key)

`oha -z10s --insecure -c 1024 https://localhost:9091`

```
Summary:
  Success rate: 100.00%
  Total:        10.0070 secs
  Slowest:      2.4513 secs
  Fastest:      0.0001 secs
  Average:      0.0095 secs
  Requests/sec: 105917.8430

  Total data:   131.32 MiB
  Size/request: 130 B
  Size/sec:     13.12 MiB

Response time histogram:
  0.000 [1]       |
  0.245 [1058184] |■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  0.490 [0]       |
  0.735 [0]       |
  0.981 [0]       |
  1.226 [0]       |
  1.471 [512]     |
  1.716 [332]     |
  1.961 [63]      |
  2.206 [61]      |
  2.451 [55]      |
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

