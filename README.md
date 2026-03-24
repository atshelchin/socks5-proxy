# socks5-proxy

High-performance multi-protocol proxy server built with Bun. Supports SOCKS5, HTTP, and HTTPS proxy on a single port with automatic protocol detection. Optional VMess (AEAD) upstream for encrypted tunneling.

## Features

- SOCKS5 proxy (RFC 1928, username/password auth)
- HTTP proxy (plain HTTP forwarding)
- HTTPS proxy (HTTP CONNECT tunneling)
- Single port, auto-detect protocol
- Optional VMess AEAD upstream (alterId=0)
  - TCP and WebSocket transport
  - TLS support
  - AES-128-GCM / ChaCha20-Poly1305
- Compiles to single binary
- One-command deploy to Linux server

## Quick Start

```bash
bun install
bun run start
```

Proxy listens on `0.0.0.0:3080` by default.

## CLI

```bash
bun run start [options]

# or compiled binary
./socks5-proxy [options]
```

| Option | Description |
|--------|-------------|
| `-p, --port <port>` | Listen port (default: 3080) |
| `-h, --host <host>` | Listen address (default: 0.0.0.0) |
| `-u, --user <user>` | Auth username |
| `--pass <pass>` | Auth password |
| `--vmess` | Enable VMess upstream (read URI from .env) |
| `--vmess vmess://...` | Enable VMess with given URI |
| `--help` | Show help |

### Examples

```bash
# Direct proxy
bun run start

# Custom port + auth
bun run start -p 8080 -u admin --pass secret

# VMess upstream from .env
bun run start --vmess

# VMess upstream with URI
bun run start --vmess "vmess://eyJ..."
```

### Client usage

```bash
curl -x socks5://127.0.0.1:3080 https://httpbin.org/get
curl -x http://127.0.0.1:3080 https://httpbin.org/get
```

## Build

```bash
# macOS
bun build --compile index.ts --outfile socks5-proxy

# Linux x64
bun build --compile --target=bun-linux-x64 index.ts --outfile socks5-proxy-linux
```

## Deploy to Server

One command — compiles, uploads, installs as systemd service:

```bash
# Direct proxy
./deploy.sh root@1.2.3.4

# Custom port
./deploy.sh root@1.2.3.4 -p 8080

# With VMess upstream
./deploy.sh root@1.2.3.4 --vmess "vmess://eyJ..."
```

After deploy:

```bash
systemctl status socks5-proxy      # Check status
systemctl restart socks5-proxy     # Restart
journalctl -u socks5-proxy -f      # View logs
vi /etc/socks5-proxy.env           # Edit config
```

## Development

```bash
bun run start    # Start dev server
bun run test     # Run tests (55 tests)
bun run bench    # Performance benchmark
```

## Performance

Benchmarked on Apple Silicon (local loopback):

| Metric | Result |
|--------|--------|
| SOCKS5 handshake | ~6,200 conn/s |
| HTTP CONNECT | ~7,200 conn/s |
| 1000 concurrent connections | 153ms |
| Data throughput | ~1,000 MB/s |
| Memory per connection | ~2.7 KB |
| Idle RSS | ~24 MB |

## Project Structure

```
index.ts              # Entry point, CLI parsing
deploy.sh             # One-command server deploy
src/
  socks5.ts           # Core proxy (SOCKS5 + HTTP, protocol detection)
  socks5.test.ts      # Proxy protocol tests (19)
  bench.ts            # Performance benchmark
  vmess/
    crypto.ts         # KDF, AEAD, AuthID, FNV1a, CRC32
    chunk.ts          # Chunked AEAD stream encoder/decoder
    vmess.ts          # VMess client (TCP + WebSocket)
    vmess.test.ts     # VMess unit tests (34)
    e2e.test.ts       # E2E with local VMess server (2)
```
