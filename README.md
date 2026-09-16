# vless-server-C

C-language VLESS over WebSocket relay server, based on [socks2vless.js](https://github.com/Cloudflare-proxy/socks2vless.js) and [Theldus/wsServer](https://github.com/Theldus/wsServer).

## Features

- VLESS protocol version 1 (UUID-based authentication)
- TCP relay (direct and via proxy)
- DNS-over-UDP relay (port 53 only, forwards to 223.5.5.5)
- SOCKS5 proxy support (with/without auth)
- HTTP/HTTPS CONNECT proxy support (with Basic auth)
- Thread-per-client architecture via wsServer

## Build

```bash
make
```

Requires `gcc`, `make`, and `pthread` (system defaults on Linux).

## Usage

```bash
./vless-server [port] [proxy_url]
```

Arguments:
- `port` — listening port (default: 28787)
- `proxy_url` — outbound proxy URL (optional)

Examples:

```bash
# Direct
./vless-server 28787

# With SOCKS5 proxy
./vless-server 28787 "socks5://user:pass@127.0.0.1:1080"

# With HTTP proxy (credentials base64url-encoded for socks, plain for http)
./vless-server 28787 "http://user:pass@127.0.0.1:8080"

# With HTTPS (TLS) proxy
./vless-server 28787 "https://127.0.0.1:443"
```

## VLESS Protocol

The first WebSocket binary frame must contain the VLESS header:

```
[version:1][uuid:16][opt_len:1][options:opt_len][cmd:1][port:2][addr_type:1][address:n][payload...]
```

- `version`: 0x01
- `uuid`: client UUID (16 bytes raw, compared with configured UUID)
- `cmd`: 0x01 = TCP, 0x02 = UDP
- Response frame prefix: `[version:1][status:1]` (status 0 = success)

## License

GPL-3.0 (same as wsServer).
