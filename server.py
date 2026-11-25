import glob
import hmac
import http.server
import json
import os
import re
import secrets
import shutil
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qs, quote, urlparse

HOST = "127.0.0.1"
PORT = 8080
VNC_WEB_PORT = int(os.environ.get("MESH_VNC_PORT", "6080"))
DIRECTORY = os.path.dirname(os.path.abspath(__file__))
_UID = os.getuid() if hasattr(os, "getuid") else os.getpid()
VNC_SOCK_DIR = os.environ.get("MESH_VNC_SOCK_DIR", os.path.join(tempfile.gettempdir(), f"mesh-vnc-{_UID}"))

ALLOWED_HOSTS = {
    f"127.0.0.1:{PORT}",
    f"localhost:{PORT}",
}
ALLOWED_ORIGINS = {
    f"http://127.0.0.1:{PORT}",
    f"http://localhost:{PORT}",
    "tauri://localhost",
    "http://tauri.localhost",
    "https://tauri.localhost",
}
STATIC_ALLOWLIST = {
    "/ui.html": ("ui.html", "text/html; charset=utf-8"),
    "/mesh-logo.png": ("mesh-logo.png", "image/png"),
    "/mesh-logo-64.png": ("mesh-logo-64.png", "image/png"),
}

SESSION_TOKEN = secrets.token_urlsafe(32)
STATE_LOCK = threading.Lock()

# tab_circuit -> {"proc": Popen, "url": str, "disp": str, "vnc_token": str, "xauth": str}
active_tabs = {}
tab_to_win = {}

config = {
    "level": "standard",
    "trackers": True,
    "fingerprint": True,
    "isolate": True,
    "erase": True,
    "route": True,
}


def ensure_vnc_sock_dir():
    os.makedirs(VNC_SOCK_DIR, mode=0o700, exist_ok=True)
    try:
        os.chmod(VNC_SOCK_DIR, 0o700)
    except OSError:
        pass


def probe_tcp(host: str, port: int, timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def network_health():
    i2p_ok = probe_tcp("127.0.0.1", 4444)
    nym_ok = probe_tcp("127.0.0.1", 1080)
    router_ok = probe_tcp("127.0.0.1", 4446)
    websockify_ok = probe_tcp("127.0.0.1", VNC_WEB_PORT)
    return {
        "i2p": i2p_ok,
        "nym": nym_ok,
        "router": router_ok,
        "websockify": websockify_ok,
        "vnc_port": VNC_WEB_PORT,
    }


def allocate_display() -> str:
    used = {int(info["disp"]) for info in active_tabs.values() if str(info.get("disp", "")).isdigit()}
    for d in range(10, 90):
        if d not in used and not os.path.exists(f"/tmp/.X11-unix/X{d}"):
            return str(d)
    for d in range(10, 90):
        if d not in used:
            return str(d)
    raise RuntimeError("no free X11 display slots available")


def cleanup_stale_socks():
    for d in glob.glob("/tmp/mesh-sock.*"):
        shutil.rmtree(d, ignore_errors=True)
    for f in glob.glob("/tmp/mesh-xauth.*"):
        try:
            os.remove(f)
        except OSError:
            pass
    if os.path.isdir(VNC_SOCK_DIR):
        for name in os.listdir(VNC_SOCK_DIR):
            try:
                os.remove(os.path.join(VNC_SOCK_DIR, name))
            except OSError:
                pass


def _cleanup_tab_artifacts(info):
    tok = info.get("vnc_token")
    if tok:
        sock_path = os.path.join(VNC_SOCK_DIR, tok)
        try:
            if os.path.exists(sock_path):
                os.remove(sock_path)
        except OSError:
            pass
    disp = info.get("disp")
    if disp and not os.path.exists(f"/proc/{info['proc'].pid}"):
        sock_x11 = f"/tmp/.X11-unix/X{disp}"
        if os.path.exists(sock_x11):
            try:
                os.remove(sock_x11)
            except OSError:
                pass
    xauth = info.get("xauth")
    if xauth:
        try:
            if os.path.exists(xauth):
                os.remove(xauth)
        except OSError:
            pass


def kill_tab(tab_name):
    with STATE_LOCK:
        info = active_tabs.pop(tab_name, None)
    if not info:
        return False
    p = info["proc"]
    killed = False
    if p.poll() is None:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            killed = True
        except (ProcessLookupError, PermissionError):
            pass
        for _ in range(10):
            if p.poll() is not None:
                break
            time.sleep(0.05)
        if p.poll() is None:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
    _cleanup_tab_artifacts(info)
    return killed


def kill_all_browsers():
    with STATE_LOCK:
        items = list(active_tabs.values())
        active_tabs.clear()
    killed = 0
    for info in items:
        p = info["proc"]
        if p.poll() is None:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                killed += 1
            except (ProcessLookupError, PermissionError):
                pass
    time.sleep(0.4)
    for info in items:
        p = info["proc"]
        if p.poll() is None:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        _cleanup_tab_artifacts(info)
    for pattern in ["bwrap.*servoshell", "/app/servoshell"]:
        subprocess.run(["pkill", "-f", pattern], check=False, capture_output=True)
    cleanup_stale_socks()
    return killed


def sanitize_url(raw):
    u = (raw or "").strip()
    if not u:
        return "http://reg.i2p/"
    if u.startswith("search:"):
        return "https://duckduckgo.com/?q=" + quote(u[7:])
    u = re.sub(r"^https://([^/]+\.i2p(?:/|$))", r"http://\1", u, flags=re.IGNORECASE)
    parsed = urlparse(u)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or u.startswith("-"):
        return None
    return u


def launch_tab(url, tab, disp=None, vnc_token=None):
    ensure_vnc_sock_dir()
    with STATE_LOCK:
        existing = active_tabs.get(tab)
    if existing:
        if disp is None:
            disp = existing["disp"]
        kill_tab(tab)

    with STATE_LOCK:
        if disp is None:
            disp = allocate_display()
        if not vnc_token:
            vnc_token = secrets.token_hex(16)
        xauth_path = os.path.join(VNC_SOCK_DIR, f".xauth-{disp}-{secrets.token_hex(8)}")
        vnc_sock = os.path.join(VNC_SOCK_DIR, vnc_token)

        env = os.environ.copy()
        env["MESH_LEVEL"] = config["level"]
        env["MESH_TRACKERS"] = "1" if config["trackers"] else "0"
        env["MESH_FINGERPRINT"] = "1" if config["fingerprint"] else "0"
        env["MESH_ISOLATE"] = "1" if config["isolate"] else "0"
        env["MESH_ERASE"] = "1" if config["erase"] else "0"
        env["MESH_ROUTE"] = "1" if config["route"] else "0"
        env["MESH_VNC_SOCK"] = vnc_sock
        env["MESH_XAUTH"] = xauth_path

        p = subprocess.Popen(
            ["./mesh-run.sh", url, tab, disp],
            cwd=DIRECTORY,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        info = {
            "proc": p,
            "url": url,
            "disp": disp,
            "vnc_token": vnc_token,
            "xauth": xauth_path,
        }
        active_tabs[tab] = info

    deadline = time.monotonic() + 4.0
    while time.monotonic() < deadline:
        if os.path.exists(vnc_sock) or p.poll() is not None:
            break
        time.sleep(0.08)
    return info


class Handler(http.server.BaseHTTPRequestHandler):
    def _valid_host(self) -> bool:
        host_hdr = (self.headers.get("Host") or "").strip().lower()
        return host_hdr in ALLOWED_HOSTS

    def _cors_origin(self):
        origin = (self.headers.get("Origin") or "").strip()
        if not origin:
            return None
        return origin if origin in ALLOWED_ORIGINS else False

    def _valid_csrf(self) -> bool:
        tok = (self.headers.get("X-Mesh-Token") or "").strip()
        return bool(tok) and hmac.compare_digest(tok, SESSION_TOKEN)

    def _send_security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")

    def _send_json(self, code, payload, origin=None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._send_security_headers()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(body)

    def _serve_static(self, req_path: str):
        target = "/ui.html" if req_path == "/" else req_path
        entry = STATIC_ALLOWLIST.get(target)
        if not entry:
            self._send_json(404, {"error": "not found"})
            return
        rel_name, ctype = entry
        full_path = os.path.join(DIRECTORY, rel_name)
        if not os.path.isfile(full_path):
            self._send_json(404, {"error": "missing asset"})
            return
        with open(full_path, "rb") as f:
            data = f.read()
        if rel_name == "ui.html":
            boot = (
                f'<script>window.__MESH_TOKEN__={json.dumps(SESSION_TOKEN)};'
                f'window.__MESH_VNC_PORT__={VNC_WEB_PORT};</script>'
            ).encode()
            if b"</head>" in data:
                data = data.replace(b"</head>", boot + b"\n</head>", 1)
            else:
                data = boot + data
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self._send_security_headers()
        if rel_name == "ui.html":
            csp = (
                f"default-src 'self'; "
                f"img-src 'self' data:; "
                f"style-src 'self' 'unsafe-inline'; "
                f"script-src 'self' 'unsafe-inline'; "
                f"connect-src 'self'; "
                f"frame-src http://127.0.0.1:{VNC_WEB_PORT} http://localhost:{VNC_WEB_PORT}; "
                f"object-src 'none'; base-uri 'none'"
            )
            self.send_header("Content-Security-Policy", csp)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _parse_params(self, parsed):
        params = parse_qs(parsed.query)
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = 0
        if length > 0:
            raw = self.rfile.read(min(length, 65536))
            ctype = (self.headers.get("Content-Type") or "").lower()
            if "application/json" in ctype:
                try:
                    obj = json.loads(raw.decode("utf-8"))
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            params[str(k)] = [str(v)]
                except (ValueError, UnicodeDecodeError):
                    return params
            elif "application/x-www-form-urlencoded" in ctype:
                for k, v in parse_qs(raw.decode("utf-8", "ignore")).items():
                    params[k] = v
        return params

    def do_OPTIONS(self):
        if not self._valid_host():
            self.send_response(403)
            self.end_headers()
            return
        origin = self._cors_origin()
        if origin is False:
            self.send_response(403)
            self.end_headers()
            return
        self.send_response(204)
        self._send_security_headers()
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Mesh-Token")
        self.end_headers()

    def do_HEAD(self):
        if not self._valid_host():
            self.send_response(403)
            self._send_security_headers()
            self.end_headers()
            return
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/"):
            self.send_response(405)
            self._send_security_headers()
            self.end_headers()
            return
        self._serve_static(parsed.path)

    def do_GET(self):
        if not self._valid_host():
            self._send_json(403, {"error": "forbidden host"})
            return
        origin = self._cors_origin()
        if origin is False:
            self._send_json(403, {"error": "forbidden origin"})
            return

        parsed = urlparse(self.path)
        if parsed.path == "/api/status":
            if not self._valid_csrf():
                self._send_json(403, {"error": "missing or invalid session token"}, origin)
                return
            net = network_health()
            with STATE_LOCK:
                tabs_meta = {
                    k: {
                        "url": v["url"],
                        "disp": v["disp"],
                        "vnc_token": v["vnc_token"],
                        "alive": v["proc"].poll() is None,
                    }
                    for k, v in active_tabs.items()
                }
            self._send_json(
                200,
                {
                    "tabs": list(tabs_meta.keys()),
                    "tab_details": tabs_meta,
                    "config": config,
                    **net,
                },
                origin,
            )
            return

        if parsed.path.startswith("/api/"):
            self._send_json(405, {"error": "mutations require POST with X-Mesh-Token"}, origin)
            return

        self._serve_static(parsed.path)

    def do_POST(self):
        if not self._valid_host():
            self._send_json(403, {"error": "forbidden host"})
            return
        origin = self._cors_origin()
        if origin is False:
            self._send_json(403, {"error": "forbidden origin"})
            return
        if not self._valid_csrf():
            self._send_json(403, {"error": "missing or invalid X-Mesh-Token"}, origin)
            return

        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/"):
            self._send_json(404, {"error": "not found"}, origin)
            return
        params = self._parse_params(parsed)
        self.handle_api_mutation(parsed.path, params, origin)

    def handle_api_mutation(self, path, params, origin):
        if path in ("/api/navigate", "/api/open"):
            url = sanitize_url(params.get("url", ["http://reg.i2p/"])[0])
            if not url:
                self._send_json(400, {"status": "error", "error": "invalid url"}, origin)
                return

            tab = params.get("tab", ["tab_1"])[0]
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", tab):
                tab = "tab_1"

            info = launch_tab(url, tab)
            self._send_json(
                200,
                {
                    "status": "ok",
                    "tab": tab,
                    "url": url,
                    "pid": info["proc"].pid,
                    "disp": info["disp"],
                    "vnc_token": info["vnc_token"],
                    "vnc_port": VNC_WEB_PORT,
                    "level": config["level"],
                },
                origin,
            )

        elif path == "/api/newroute":
            old_tab = params.get("old_tab", [""])[0]
            new_tab = params.get("tab", ["tab_1"])[0]
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", new_tab):
                new_tab = "tab_1"
            raw_url = params.get("url", [""])[0]
            if old_tab and re.fullmatch(r"[A-Za-z0-9_-]{1,32}", old_tab):
                kill_tab(old_tab)
            kill_tab(new_tab)
            restarted = False
            info = None
            if raw_url:
                url = sanitize_url(raw_url)
                if url:
                    info = launch_tab(url, new_tab)
                    restarted = True
            net = network_health()
            self._send_json(
                200,
                {
                    "status": "ok",
                    "tab": new_tab,
                    "restarted": restarted,
                    "disp": info["disp"] if info else None,
                    "vnc_token": info["vnc_token"] if info else None,
                    "vnc_port": VNC_WEB_PORT,
                    **net,
                },
                origin,
            )

        elif path == "/api/config":
            changed = False
            level = params.get("level", [None])[0]
            if level in ("standard", "safer", "safest") and config["level"] != level:
                config["level"] = level
                changed = True

            pref = params.get("pref", [None])[0]
            val = params.get("val", [None])[0]
            if pref in config and pref != "level" and val in ("0", "1", "true", "false"):
                new_val = val in ("1", "true")
                if config[pref] != new_val:
                    config[pref] = new_val
                    changed = True

            reloaded_tabs = {}
            if changed:
                with STATE_LOCK:
                    snapshot = list(active_tabs.items())
                for tab, info in snapshot:
                    if info["proc"].poll() is None:
                        updated = launch_tab(info["url"], tab, disp=info["disp"])
                        reloaded_tabs[tab] = {
                            "disp": updated["disp"],
                            "vnc_token": updated["vnc_token"],
                        }

            self._send_json(
                200,
                {
                    "status": "ok",
                    "config": config,
                    "reloaded": changed,
                    "tabs": reloaded_tabs,
                },
                origin,
            )

        elif path == "/api/focus":
            tab = params.get("tab", [""])[0]
            win = tab_to_win.get(tab)
            if win:
                subprocess.run(["xdotool", "windowraise", win], check=False, capture_output=True)
            self._send_json(200, {"status": "ok"}, origin)

        elif path == "/api/close":
            tab = params.get("tab", [""])[0]
            closed = kill_tab(tab) if re.fullmatch(r"[A-Za-z0-9_-]{1,32}", tab) else False
            self._send_json(200, {"status": "closed", "closed": closed}, origin)

        elif path == "/api/ident":
            killed = kill_all_browsers()
            self._send_json(200, {"status": "ok", "killed": killed}, origin)

        else:
            self._send_json(404, {"error": "not found"}, origin)

    def log_message(self, format, *args):
        pass


class ReusableTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    ensure_vnc_sock_dir()
    cleanup_stale_socks()
    print(f"Mesh Server locked to http://{HOST}:{PORT} (VNC Unix sockets in {VNC_SOCK_DIR})", flush=True)
    with ReusableTCPServer((HOST, PORT), Handler) as httpd:
        httpd.serve_forever()
