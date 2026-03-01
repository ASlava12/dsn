# Transport usage examples

This file provides practical CLI examples for currently implemented transports.

## Common command shape

```bash
dsn transport listen <transport_url>
dsn transport connect <transport_url>
```

## TCP

```bash
dsn transport listen tcp://127.0.0.1:7000
dsn transport connect tcp://127.0.0.1:7000
```

## UDP

```bash
dsn transport listen udp://127.0.0.1:7001
dsn transport connect udp://127.0.0.1:7001
```

UDP stdin->network is line-based: each input line is sent as one datagram payload.

## TLS

```bash
dsn transport listen "tls://127.0.0.1:7443?cert=/etc/dsn/server-cert.pem&key=/etc/dsn/server-key.pem"
dsn transport connect "tls://127.0.0.1:7443?ca=/etc/dsn/ca.pem&servername=localhost"
```

If `ca` is omitted on client side, system roots are used.

## QUIC

```bash
dsn transport listen "quic://127.0.0.1:8443?cert=/etc/dsn/server-cert.pem&key=/etc/dsn/server-key.pem"
dsn transport connect "quic://127.0.0.1:8443?ca=/etc/dsn/ca.pem&servername=localhost"
```

QUIC v0 stand behavior: first connection + first bidi stream is used as stream tunnel.

## WS / WSS

```bash
dsn transport listen "ws://127.0.0.1:8080/chat"
dsn transport connect "ws://127.0.0.1:8080/chat?origin=https://example.test&header.X-Demo=1"
```

```bash
dsn transport listen "wss://127.0.0.1:8444/chat?cert=/etc/dsn/server-cert.pem&key=/etc/dsn/server-key.pem"
dsn transport connect "wss://127.0.0.1:8444/chat?ca=/etc/dsn/ca.pem&servername=localhost&origin=https://example.test"
```

## H2 tunnel (test mode)

```bash
dsn transport listen "h2://127.0.0.1:9443/tunnel?cert=/etc/dsn/server-cert.pem&key=/etc/dsn/server-key.pem"
dsn transport connect "h2://127.0.0.1:9443/tunnel?ca=/etc/dsn/ca.pem&servername=localhost"
```

## G2 tunnel over TLS (test mode)

```bash
dsn transport listen "g2://127.0.0.1:9553/tunnel.Tunnel/Stream?cert=/etc/dsn/server-cert.pem&key=/etc/dsn/server-key.pem"
dsn transport connect "g2://127.0.0.1:9553/tunnel.Tunnel/Stream?ca=/etc/dsn/ca.pem&servername=localhost"
```

`g2` currently uses a minimal gRPC-style framed byte tunnel for testing.

## Unix socket

```bash
dsn transport listen unix:///tmp/dsn.sock
dsn transport connect unix:///tmp/dsn.sock
```
