#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

export MESH_VNC_PORT="${MESH_VNC_PORT:-6080}"
export MESH_VNC_SOCK_DIR="${MESH_VNC_SOCK_DIR:-/tmp/mesh-vnc-$(id -u)}"

mkdir -p "$MESH_VNC_SOCK_DIR"
chmod 700 "$MESH_VNC_SOCK_DIR"
rm -f "$MESH_VNC_SOCK_DIR"/* 2>/dev/null || true

PIDS=()
cleanup() {
  pkill -9 -f "/app/servoshell" 2>/dev/null || true
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  rm -f "$MESH_VNC_SOCK_DIR"/* 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Single localhost-only websockify gateway mapped to per-tab Unix domain sockets (mode 0600).
# Unauthenticated clients without a secret per-tab token receive 404/close; zero TCP VNC ports (5900+) exist.
PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}" websockify \
  --web="$PWD/novnc" \
  --token-plugin=vnc_token_plugin.SafeUnixSocketDirectory \
  --token-source="$MESH_VNC_SOCK_DIR" \
  "127.0.0.1:${MESH_VNC_PORT}" >/tmp/mesh-websockify.log 2>&1 &
PIDS+=($!)

if [ -x "$PWD/nym-socks5-client" ]; then
  ./nym-socks5-client run --id mesh-nym >/tmp/nym.log 2>&1 &
  PIDS+=($!)
fi

python3 mesh-router.py >/tmp/mesh-router.log 2>&1 &
PIDS+=($!)
python3 mesh-scrubber.py >/dev/null 2>&1 &
PIDS+=($!)
python3 server.py &
PIDS+=($!)

for _ in $(seq 1 50); do
  (echo > /dev/tcp/127.0.0.1/8080) 2>/dev/null && break
  sleep 0.1
done

echo "Launching Mesh Browser..."
python3 "$PWD/mesh-app.py" &
MESH_PID=$!
wait "$MESH_PID"
