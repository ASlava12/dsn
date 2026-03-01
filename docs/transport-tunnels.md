# H2 / g2 test tunnel mode (v0)

`h2://` and `g2://` transports are currently implemented as **byte tunnels for stand testing**.

- They are intended to support `dsn transport listen/connect` stdin/stdout workflows.
- They are **not** final overlay semantics.

## h2

- Server accepts one TLS connection and the first HTTP/2 POST request for configured `path`.
- Request body bytes are piped to local stream read side.
- Local stream write side is piped back to HTTP/2 response body.

## g2

- Implemented as an h2-based tunnel with gRPC-style framed bytes (`1-byte flag + 4-byte len + payload`).
- Path should be set to service-like path (e.g. `/tunnel.Tunnel/Stream`).
- This is a minimal compatibility bridge for tunnel testing, not a full typed gRPC API.

## TLS and LB notes

- For `h2`/`g2`, listener requires `cert` + `key`.
- Client trusts:
  - custom CA via `ca=...`, or
  - system roots when `ca` is omitted.
- `servername` override is supported and recommended behind LB/proxies.
