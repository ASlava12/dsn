#!/usr/bin/env bash
set -euo pipefail

cd /workspace
cargo build -p dsn-cli >/dev/null

# Wait until admin sockets are reachable.
for i in $(seq 1 60); do
  if /workspace/target/debug/dsn-cli --config /state/bootstrap/bootstrap.toml node status --state-dir /state/bootstrap/node-state >/tmp/bootstrap.status 2>/dev/null; then
    break
  fi
  sleep 1
done

/workspace/target/debug/dsn-cli --config /state/bootstrap/bootstrap.toml node status --state-dir /state/bootstrap/node-state
/workspace/target/debug/dsn-cli --config /state/node2/node2.toml node status --state-dir /state/node2/node-state
/workspace/target/debug/dsn-cli --config /state/relay/relay.toml node status --state-dir /state/relay/node-state

/workspace/target/debug/dsn-cli --config /state/node2/node2.toml dht namespaces

# Network/runtime checks that exercise handshake/ping, DHT find_node, relay route, and rekey logic.
cargo test -p dsn-core two_nodes_exchange_ping_over_control
cargo test -p dsn-core find_node_request_goes_over_network_with_retries_timeouts_manager
cargo test -p dsn-core route_send_node_goes_via_one_relay_and_updates_ttl_cache
cargo test -p dsn-core rekey_triggers_by_bytes_or_age
