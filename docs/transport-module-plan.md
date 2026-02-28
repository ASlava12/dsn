# Transport module layout plan

This document captures the current workspace scan and the target modular decomposition for transport work.

## Workspace scan (current)

- Workspace members:
  - `dsn-core` (config, identity, schema/validation helpers)
  - `dsn-cli` (clap entrypoint, command dispatching, config command handlers)
- Existing CLI command tree currently includes only `dsn config ...`.
- Config and identity logic are centralized in `dsn-core` and reused by `dsn-cli`.

## Target module layout

### `dsn-core`

- `src/transport/endpoint.rs`
  - Canonical `TransportEndpoint` parser (`FromStr`), transport scheme enum, reserved query params.
- `src/transport/mod.rs`
  - Re-exports and shared transport types.
- `src/transport/runtime/` *(future stage)*
  - `mod.rs` (trait for listener/connector abstraction)
  - `tcp.rs` (default enabled)
  - `udp.rs` (default enabled)
  - `tls.rs` (`transport-tls` feature)
  - `quic.rs` (`transport-quic` feature)
  - `ws.rs` (`transport-ws` feature)
  - `h2.rs` (`transport-h2` feature)
  - `g2.rs` (`transport-g2` feature)

### `dsn-cli`

- `src/cmd/cli.rs`
  - Add `transport` command tree:
    - `dsn transport listen <transport_url>`
    - `dsn transport connect <transport_url>`
- `src/app/transport.rs` *(future stage)*
  - CLI command handler -> endpoint parse -> runtime dispatch.
- `src/app/mod.rs`
  - Route `Commands::Transport(...)` without touching existing `config` flow.

## Dependency and feature strategy

### Start (minimal baseline)

- Add one parser dependency in `dsn-core`:
  - `url = "2"` for strict URL parsing/validation.
- No new runtime transport dependencies in stage 1.

### Planned cargo features for runtime expansion

In `dsn-core/Cargo.toml`:

- `default = ["transport-tcp", "transport-udp"]`
- `transport-tcp = []`
- `transport-udp = []`
- `transport-tls = []`
- `transport-quic = []`
- `transport-ws = ["transport-tls"]`
- `transport-h2 = ["transport-tls"]`
- `transport-g2 = ["transport-h2"]`

Feature-gated dependencies should be added only when implementation lands.

## Compatibility rule

- `dsn config ...` command tree remains unchanged and backward-compatible.
