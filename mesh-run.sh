#!/usr/bin/env bash
set -euo pipefail

URL="${1:-http://reg.i2p/}"
TAB="${2:-tab1}"
DISP="${3:-10}"
APP_DIR="$(cd "$(dirname "$0")" && pwd)"

LEVEL="${MESH_LEVEL:-standard}"
TRACKERS="${MESH_TRACKERS:-1}"
FINGERPRINT="${MESH_FINGERPRINT:-1}"
ISOLATE="${MESH_ISOLATE:-1}"
ERASE="${MESH_ERASE:-1}"
ROUTE="${MESH_ROUTE:-1}"
VNC_SOCK="${MESH_VNC_SOCK:-}"
OWN_XAUTH=0
if [ -n "${MESH_XAUTH:-}" ]; then
  XAUTH_FILE="$MESH_XAUTH"
else
  XAUTH_FILE="$(mktemp /tmp/mesh-xauth.XXXXXXXXXX)"
  OWN_XAUTH=1
fi

case "$URL" in
  http://*|https://*) ;;
  *) echo "Blocked invalid URL scheme: $URL"; exit 1 ;;
esac

case "$DISP" in
  ''|*[!0-9]*) echo "Invalid display number: $DISP"; exit 1 ;;
esac

# Fail-closed proxy enforcement: never bypass mesh-router.py (:4446) onto raw i2pd (:4444),
# because :4444 lacks private/LAN IP filtering and clearnet Nym routing.
if [ "$ROUTE" = "1" ]; then
  (echo > /dev/tcp/127.0.0.1/4446) 2>/dev/null || {
    echo "Fail-closed: mesh-router.py is not listening on 127.0.0.1:4446"
    exit 1
  }
fi

mkdir -p "$APP_DIR/.clean-share"

SOCK_DIR="$(mktemp -d /tmp/mesh-sock.XXXXXX)"
chmod 700 "$SOCK_DIR"

XPID=""
WMPID=""
VNCPID=""
SOCAT_PID=""

cleanup() {
  [ -n "$SOCAT_PID" ] && kill "$SOCAT_PID" 2>/dev/null || true
  [ -n "$VNCPID" ] && kill "$VNCPID" 2>/dev/null || true
  [ -n "$WMPID" ] && kill "$WMPID" 2>/dev/null || true
  [ -n "$XPID" ] && kill "$XPID" 2>/dev/null || true
  rm -rf "$SOCK_DIR"
  rm -f "$XAUTH_FILE"
  [ -n "$XPID" ] && rm -f "/tmp/.X11-unix/X${DISP}" 2>/dev/null || true
  [ -n "$VNC_SOCK" ] && rm -f "$VNC_SOCK"
}
trap cleanup EXIT INT TERM

# Per-tab Xauthority cookie (mode 0600) + dedicated Xvfb display per tab
umask 077
if [ "$OWN_XAUTH" -eq 0 ]; then
  rm -f "$XAUTH_FILE"
  : > "$XAUTH_FILE"
fi
chmod 600 "$XAUTH_FILE"
COOKIE="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
xauth -f "$XAUTH_FILE" add ":${DISP}" . "$COOKIE" >/dev/null 2>&1

if [ -S "/tmp/.X11-unix/X${DISP}" ] && ! pgrep -f "Xvfb :${DISP} " >/dev/null 2>&1; then
  rm -f "/tmp/.X11-unix/X${DISP}" 2>/dev/null || true
fi

if [ ! -S "/tmp/.X11-unix/X${DISP}" ]; then
  Xvfb ":${DISP}" -auth "$XAUTH_FILE" -screen 0 1600x840x24 +extension GLX +render -noreset -nolisten tcp >/dev/null 2>&1 &
  XPID=$!
  for _ in $(seq 1 30); do
    [ -S "/tmp/.X11-unix/X${DISP}" ] && break
    sleep 0.05
  done
  [ -S "/tmp/.X11-unix/X${DISP}" ] || { echo "Failed to start Xvfb :${DISP}"; exit 1; }
fi

DISPLAY=":${DISP}" XAUTHORITY="$XAUTH_FILE" setxkbmap us >/dev/null 2>&1 || true
DISPLAY=":${DISP}" XAUTHORITY="$XAUTH_FILE" openbox --config-file "$APP_DIR/openbox-rc.xml" >/dev/null 2>&1 &
WMPID=$!

# Bind x11vnc strictly to a mode-0600 Unix domain socket (-rfbport 0 -rfbportv6 0 -no6 -noipv6): zero TCP listeners on IPv4 or IPv6.
if [ -n "$VNC_SOCK" ]; then
  rm -f "$VNC_SOCK"
  x11vnc -display ":${DISP}" -auth "$XAUTH_FILE" -unixsock "$VNC_SOCK" -rfbport 0 -rfbportv6 0 -no6 -noipv6 -nopw -forever -shared -noxdamage -xkb -repeat >/dev/null 2>&1 &
  VNCPID=$!
  for _ in $(seq 1 40); do
    [ -S "$VNC_SOCK" ] && break
    sleep 0.05
  done
  [ -S "$VNC_SOCK" ] && chmod 600 "$VNC_SOCK" 2>/dev/null || true
fi

if [ "$ROUTE" = "1" ]; then
  socat UNIX-LISTEN:"$SOCK_DIR/i2p.sock",fork,mode=600 "TCP:127.0.0.1:4446" &
  SOCAT_PID=$!
fi

EXTRA_ARGS=()
[ "$ERASE" = "1" ] && EXTRA_ARGS+=(--temporary-storage)
[ "$TRACKERS" = "1" ] && [ -f "$APP_DIR/blocklist.hosts" ] && EXTRA_ARGS+=(--host-file=/app/blocklist.hosts)

if [ "$FINGERPRINT" = "1" ]; then
  EXTRA_ARGS+=(
    --userscripts=/app/userscripts
    "--pref=user_agent=Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0"
  )
fi

if [ "$LEVEL" = "safer" ] || [ "$LEVEL" = "safest" ]; then
  EXTRA_ARGS+=(
    "--pref=js_disable_jit=true"
    "--pref=js_ion_enabled=false"
    "--pref=js_offthread_compilation_enabled=false"
    "--pref=js_wasm_baseline_enabled=false"
    "--pref=js_wasm_ion_enabled=false"
    "--pref=dom_webgl2_enabled=false"
    "--pref=dom_fontface_enabled=false"
    "--pref=dom_serviceworker_enabled=false"
    "--pref=dom_sharedworker_enabled=false"
    "--pref=dom_worklet_enabled=false"
  )
fi

if [ "$LEVEL" = "safest" ]; then
  EXTRA_ARGS+=(
    "--pref=js_baseline_interpreter_enabled=false"
    "--pref=dom_indexeddb_enabled=false"
    "--pref=dom_cookiestore_enabled=false"
    "--pref=dom_storage_manager_api_enabled=false"
    "--pref=dom_credential_management_enabled=false"
    "--pref=dom_wakelock_enabled=false"
    "--pref=dom_async_clipboard_enabled=false"
    "--pref=dom_canvas_text_enabled=false"
    "--pref=dom_canvas_capture_enabled=false"
    "--pref=dom_allow_scripts_to_close_windows=false"
  )
  [ -f "$APP_DIR/safest.css" ] && EXTRA_ARGS+=(--user-stylesheet=/app/safest.css)
fi

HOME_MOUNT=(--tmpfs /home/mesh)
if [ "$ISOLATE" = "0" ] && [ "$ERASE" = "0" ]; then
  SHARED_PROFILE="$APP_DIR/.shared-profile"
  mkdir -p "$SHARED_PROFILE"
  chmod 700 "$SHARED_PROFILE"
  HOME_MOUNT=(--bind "$SHARED_PROFILE" /home/mesh)
fi

NET_FLAGS=(--unshare-net)
PROXY_ARGS=(
  --pref="network_http_proxy_uri=http://127.0.0.1:4444"
  --pref="network_https_proxy_uri=http://127.0.0.1:4444"
)
INNER_CMD='
  socat TCP-LISTEN:4444,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:/tmp/mesh-sock/i2p.sock &
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -e /proc/net/tcp ] && grep -qi ":115C " /proc/net/tcp && break
    sleep 0.03
  done
  exec /app/servoshell -b "$@"
'
if [ "$ROUTE" = "0" ]; then
  NET_FLAGS=()
  PROXY_ARGS=()
  INNER_CMD='exec /app/servoshell -b "$@"'
fi

bwrap \
  --ro-bind /usr /usr --ro-bind-try /lib /lib --ro-bind-try /lib64 /lib64 \
  --ro-bind-try "$APP_DIR/fonts" /usr/share/fonts \
  --ro-bind-try "$APP_DIR/fonts" /usr/local/share/fonts \
  --ro-bind-try /bin /bin \
  --ro-bind-try /etc/ssl /etc/ssl --ro-bind-try /etc/ca-certificates /etc/ca-certificates \
  --ro-bind-try /etc/ld.so.cache /etc/ld.so.cache \
  --ro-bind-try /etc/resolv.conf /etc/resolv.conf \
  --dir /app \
  --ro-bind "$APP_DIR/servoshell" /app/servoshell \
  --ro-bind "$APP_DIR/mesh-prefs.json" /app/mesh-prefs.json \
  --ro-bind "$APP_DIR/fonts.conf" /app/fonts.conf \
  --ro-bind "$APP_DIR/fonts" /app/fonts \
  --ro-bind "$APP_DIR/userscripts" /app/userscripts \
  --ro-bind-try "$APP_DIR/resources" /app/resources \
  --ro-bind-try "$APP_DIR/blocklist.hosts" /app/blocklist.hosts \
  --ro-bind-try "$APP_DIR/safest.css" /app/safest.css \
  --dev /dev --proc /proc --tmpfs /dev/shm --tmpfs /tmp "${HOME_MOUNT[@]}" \
  --dir /home/mesh/Share --ro-bind "$APP_DIR/.clean-share" /home/mesh/Share --dir /tmp/xdg \
  --ro-bind "$XAUTH_FILE" /tmp/.Xauthority \
  --bind "/tmp/.X11-unix/X${DISP}" "/tmp/.X11-unix/X${DISP}" \
  --bind "$SOCK_DIR" /tmp/mesh-sock \
  --cap-drop ALL \
  "${NET_FLAGS[@]}" --unshare-pid --unshare-uts --unshare-cgroup \
  --die-with-parent --new-session --clearenv \
  --setenv FONTCONFIG_FILE /app/fonts.conf \
  --setenv PATH /usr/bin:/bin --setenv HOME /home/mesh \
  --setenv XDG_RUNTIME_DIR /tmp/xdg --setenv DISPLAY ":${DISP}" \
  --setenv MESH_TAB "$TAB" \
  --setenv XAUTHORITY /tmp/.Xauthority \
  --setenv TZ UTC --setenv LANG en_US.UTF-8 \
  --chdir /app \
  /bin/sh -c "$INNER_CMD" -- \
  --prefs-file=/app/mesh-prefs.json \
  "${PROXY_ARGS[@]}" \
  --pref="network_http_cache_disabled=true" \
  --pref="network_use_webpki_roots=true" \
  --screen-size=1600x840 --window-size=1600x840 --device-pixel-ratio=1.0 \
  "${EXTRA_ARGS[@]}" \
  "$URL"
