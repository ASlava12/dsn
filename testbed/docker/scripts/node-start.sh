#!/usr/bin/env bash
set -euo pipefail

CFG_PATH="${CFG_PATH:-/state/config.toml}"
STATE_DIR="${STATE_DIR:-/state/node-state}"
LISTEN_JSON="${LISTEN_JSON:-[\"ws://0.0.0.0:8080/chat\",\"tcp://0.0.0.0:4101\"]}"
BOOTSTRAP_JSON="${BOOTSTRAP_JSON:-[]}"

mkdir -p "$(dirname "$CFG_PATH")" "$STATE_DIR"

if [ ! -f "$CFG_PATH" ]; then
  /workspace/target/debug/dsn-cli --config "$CFG_PATH" config init
fi

/workspace/target/debug/dsn-cli --config "$CFG_PATH" config set --force participate_in_dht true
/workspace/target/debug/dsn-cli --config "$CFG_PATH" config set --force address_mode all
/workspace/target/debug/dsn-cli --config "$CFG_PATH" config set --force listen "$LISTEN_JSON"
/workspace/target/debug/dsn-cli --config "$CFG_PATH" config set --force bootstrap_peers "$BOOTSTRAP_JSON"

exec /workspace/target/debug/dsn-cli --config "$CFG_PATH" node run --state-dir "$STATE_DIR"
