# Filtering HTTP/HTTPS Forward Proxy (C++)

A small forward proxy written in C++ that sits between a client and the internet,
relays HTTP traffic, tunnels HTTPS using `CONNECT`, and blocks domains listed in a
blocklist. Built to understand how secure web gateways enforce policy on traffic.

## Features

- Parses HTTP requests (request line + `Host` header) and forwards them to the origin server
- HTTPS support via `CONNECT` tunneling (bytes are relayed, nothing is decrypted)
- Domain blocklist (`blocklist.txt`); blocked hosts receive `403 Forbidden`
- Logs every request: timestamp, client IP, host, ALLOW/BLOCK
- Handles multiple clients concurrently using a fixed-size thread pool

## Architecture

```
Browser/curl  -->  Proxy (this project)  -->  Origin server
                      |
                      +-- policy check (blocklist.txt)
                      +-- logging (proxy.log)
```

1. Accept a client connection and hand it to a worker thread from the pool
2. Read and parse the request
3. Check the host against the blocklist
4. If blocked, send 403 and log it. If allowed, connect to the origin and relay data both ways
5. For `CONNECT host:443`, reply `200 Connection Established` and relay raw bytes

## Build and run

```bash
g++ -std=c++17 -pthread src/*.cpp -o proxy
./proxy 8888
```

## Try it

```bash
# Allowed HTTP request through the proxy
curl -x http://localhost:8888 http://example.com

# Allowed HTTPS request (CONNECT tunnel)
curl -x http://localhost:8888 https://example.com

# Blocked domain (listed in blocklist.txt)
curl -x http://localhost:8888 http://blocked-site.com   # -> 403 Forbidden
```

## Design decisions

- **TCP sockets:** reliable, ordered delivery is required for HTTP
- **CONNECT tunneling:** HTTPS is encrypted end to end, so the proxy can only see the
  destination host, not the URL path or content
- **Thread pool:** a fixed number of worker threads avoids the cost of creating a thread
  per connection and puts a cap on resource usage under load

## Limitations and future work

- No TLS inspection (would require a client-trusted proxy certificate)
- A thread pool still blocks one thread per active connection, so it does not scale
  like an `epoll` event loop
- Limited handling of chunked transfer encoding and HTTP keep-alive
- Possible additions: per-IP rate limiting, DNS cache, `epoll`

## Testing

- Tested with multiple simultaneous connections by running parallel `curl` requests
- Manually verified allow, block, and HTTPS tunnel behavior with `curl`

## Progress

Tick these off as you build, then delete this section when everything is done.

- [ ] TCP listener and HTTP request parsing
- [ ] HTTP forwarding to origin server
- [ ] `CONNECT` tunneling for HTTPS
- [ ] Blocklist policy engine (403 response)
- [ ] Request logging
- [ ] Thread pool
- [ ] Partial reads, timeouts, connection resets
