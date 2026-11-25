import contextlib
import ipaddress
import re
import socket
import socketserver
import struct
import threading
from urllib.parse import urlsplit

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 4446
I2P_HOST, I2P_PORT = "127.0.0.1", 4444
NYM_HOST, NYM_PORT = "127.0.0.1", 1080

HOSTNAME_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)
ALLOWED_HTTP_VERSIONS = {"HTTP/1.1", "HTTP/1.0"}
ALLOWED_METHODS = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"}

STRIP_REQ_HEADERS = {
    b"host",
    b"proxy-connection",
    b"connection",
    b"if-none-match",
    b"if-modified-since",
    b"dnt",
    b"accept-language",
    b"referer",
}

HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
)


def valid_header_lines(lines) -> bool:
    """Reject bare CR/LF, NUL/CTL bytes, and HTTP request smuggling (CL+TE or duplicate CL)."""
    seen_cl = False
    seen_te = False
    for idx, ln in enumerate(lines):
        if b"\r" in ln or b"\n" in ln or b"\x00" in ln:
            return False
        for b in ln:
            if b < 0x20 and b != 0x09:
                return False
        if idx == 0:
            continue
        if b":" not in ln:
            return False
        name = ln.split(b":", 1)[0].strip().lower()
        if not name or any(c in name for c in b" \t"):
            return False
        if name == b"content-length":
            if seen_cl or seen_te:
                return False
            val = ln.split(b":", 1)[1].strip()
            if not val.isdigit():
                return False
            seen_cl = True
        elif name == b"transfer-encoding":
            if seen_cl or seen_te:
                return False
            seen_te = True
    return True


def normalize_host(host: str) -> str:
    return (host or "").strip().strip("[]").rstrip(".").lower()


def is_valid_host(host: str) -> bool:
    h = normalize_host(host)
    if not h or len(h) > 253:
        return False
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.fullmatch(h))


def is_i2p(host: str) -> bool:
    h = normalize_host(host)
    if not HOSTNAME_RE.fullmatch(h):
        return False
    return h == "i2p" or h.endswith(".i2p")


def is_private_ip(host: str) -> bool:
    h = normalize_host(host)
    if not h or h in ("localhost", "localhost.localdomain") or h.endswith((".localhost", ".local")):
        return True
    try:
        ip = ipaddress.ip_address(h)
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        return (
            (not ip.is_global)
            or ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )
    except ValueError:
        return not HOSTNAME_RE.fullmatch(h)


def scrub_http_request(lines, target_host: str, host_authority: str, new_req_line=None):
    out = [new_req_line if new_req_line else lines[0]]
    out.append(f"Host: {host_authority}".encode("latin1"))
    norm_target = normalize_host(target_host)
    for ln in lines[1:]:
        name = ln.split(b":", 1)[0].strip().lower()
        if name == b"referer":
            # Keep only same-host referer; strip all cross-site referers
            ref_val = ln.split(b":", 1)[1].strip().decode("latin1", "ignore")
            try:
                ref_host = urlsplit(ref_val).hostname
                if ref_host and normalize_host(ref_host) == norm_target:
                    out.append(ln)
            except ValueError:
                continue
            continue
        if name in STRIP_REQ_HEADERS:
            continue
        out.append(ln)
    out.append(b"Accept-Language: en-US,en;q=0.5")
    out.append(b"Connection: close")
    return out


def socks5_connect(host: str, port: int, timeout: float = 25.0) -> socket.socket:
    host_b = normalize_host(host).encode("idna")
    if len(host_b) > 255:
        raise ValueError("hostname too long")
    s = socket.create_connection((NYM_HOST, NYM_PORT), timeout=timeout)
    try:
        s.sendall(b"\x05\x01\x00")
        resp = s.recv(2)
        if len(resp) != 2 or resp != b"\x05\x00":
            raise ConnectionError("SOCKS5 auth failed")

        req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack("!H", port)
        s.sendall(req)

        hdr = b""
        while len(hdr) < 4:
            chunk = s.recv(4 - len(hdr))
            if not chunk:
                raise ConnectionError("SOCKS5 EOF")
            hdr += chunk
        if hdr[1] != 0:
            raise ConnectionError(f"SOCKS5 error code {hdr[1]}")

        atyp = hdr[3]
        if atyp == 1:
            s.recv(6)
        elif atyp == 4:
            s.recv(18)
        elif atyp == 3:
            ln = s.recv(1)
            if ln:
                s.recv(ln[0] + 2)
        s.settimeout(300.0)
        return s
    except (OSError, ValueError):
        s.close()
        raise


def relay(a: socket.socket, b: socket.socket):
    def pump(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            return
        finally:
            with contextlib.suppress(OSError):
                dst.shutdown(socket.SHUT_WR)

    t1 = threading.Thread(target=pump, args=(a, b), daemon=True)
    t2 = threading.Thread(target=pump, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


def send_err(client: socket.socket, code: int, msg: str):
    reason = {400: "Bad Request", 403: "Forbidden", 502: "Bad Gateway"}.get(code, "Error")
    body = msg.encode("utf-8", "replace")
    hdr = (
        f"HTTP/1.1 {code} {reason}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    try:
        client.sendall(hdr + body)
    except OSError:
        return


def handle_i2p_connect(client: socket.socket, host: str, port: int, initial_rest: bytes):
    """Demux Servo HTTP-inside-CONNECT:443 vs real TLS CONNECT for *.i2p domains."""
    clean_host = normalize_host(host)
    if not is_i2p(clean_host) or not (1 <= port <= 65535):
        return

    client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    inner = initial_rest
    client.settimeout(30.0)
    while len(inner) < 8:
        chunk = client.recv(4096)
        if not chunk:
            return
        inner += chunk
        if inner[0] == 0x16 or b"\r\n" in inner:
            break

    is_cleartext_http = any(inner.upper().startswith(m) for m in HTTP_METHODS)
    if not is_cleartext_http:
        connect_hdr = (
            f"CONNECT {clean_host}:{port} HTTP/1.1\r\n"
            f"Host: {clean_host}:{port}\r\n"
            f"Proxy-Connection: keep-alive\r\n\r\n"
        ).encode("latin1")
        up = socket.create_connection((I2P_HOST, I2P_PORT), timeout=30.0)
        try:
            up.settimeout(60.0)
            up.sendall(connect_hdr)
            resp = b""
            while b"\r\n\r\n" not in resp and len(resp) < 16384:
                c = up.recv(4096)
                if not c:
                    return
                resp += c
            status_line = resp.split(b"\r\n", 1)[0]
            if b" 200 " not in status_line:
                return
            rem = resp.split(b"\r\n\r\n", 1)[1]
            if rem:
                client.sendall(rem)
            up.settimeout(300.0)
            client.settimeout(300.0)
            up.sendall(inner)
            relay(client, up)
        finally:
            up.close()
        return

    while b"\r\n\r\n" not in inner and len(inner) < 65536:
        chunk = client.recv(4096)
        if not chunk:
            return
        inner += chunk

    sep = inner.find(b"\r\n\r\n")
    if sep == -1:
        return
    in_head = inner[:sep]
    in_rest = inner[sep + 4:]
    in_lines = in_head.split(b"\r\n")
    if not valid_header_lines(in_lines):
        send_err(client, 400, "Invalid inner HTTP header\n")
        return

    in_parts = in_lines[0].decode("latin1").split(" ")
    if len(in_parts) != 3:
        send_err(client, 400, "Malformed request line\n")
        return
    in_method, in_target, in_ver = in_parts[0].upper(), in_parts[1], in_parts[2].upper()
    if in_method not in ALLOWED_METHODS or in_ver not in ALLOWED_HTTP_VERSIONS:
        send_err(client, 400, "Unsupported HTTP method or version\n")
        return

    eff_port = 80 if port in (80, 443) else port
    host_authority = f"{clean_host}:{eff_port}" if eff_port != 80 else clean_host

    if in_target.lower().startswith(("http://", "https://")):
        parsed_in = urlsplit(in_target)
        if parsed_in.scheme.lower() != "http" or normalize_host(parsed_in.hostname or "") != clean_host:
            send_err(client, 403, "Blocked authority mismatch inside CONNECT\n")
            return
        rel_path = (parsed_in.path or "/") + (f"?{parsed_in.query}" if parsed_in.query else "")
    else:
        if not in_target.startswith("/"):
            send_err(client, 400, "Invalid origin-form path\n")
            return
        rel_path = in_target

    if any(ch in rel_path for ch in ("\r", "\n", " ", "\t", "\x00")):
        send_err(client, 400, "Invalid request target\n")
        return

    abs_url = f"http://{host_authority}{rel_path}"
    new_req_line = f"{in_method} {abs_url} {in_ver}".encode("latin1")
    scrubbed = (
        b"\r\n".join(scrub_http_request(in_lines, clean_host, host_authority, new_req_line))
        + b"\r\n\r\n"
        + in_rest
    )
    up = socket.create_connection((I2P_HOST, I2P_PORT), timeout=30.0)
    try:
        up.settimeout(300.0)
        client.settimeout(300.0)
        up.sendall(scrubbed)
        relay(client, up)
    finally:
        up.close()


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        client.settimeout(30.0)
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            chunk = client.recv(4096)
            if not chunk:
                return
            buf += chunk

        sep = buf.find(b"\r\n\r\n")
        if sep == -1:
            return
        head_bytes = buf[:sep]
        rest = buf[sep + 4:]
        lines = head_bytes.split(b"\r\n")
        if not valid_header_lines(lines):
            send_err(client, 400, "Invalid HTTP header\n")
            return
        parts = lines[0].decode("latin1").split(" ")
        if len(parts) != 3:
            send_err(client, 400, "Malformed request line\n")
            return
        method, target, version = parts[0].upper(), parts[1], parts[2].upper()
        if version not in ALLOWED_HTTP_VERSIONS:
            send_err(client, 400, "Unsupported HTTP version\n")
            return
        client.settimeout(300.0)

        if method == "CONNECT":
            try:
                if target.startswith("["):
                    hp = target[1:].split("]:", 1)
                    raw_host, port = hp[0], int(hp[1]) if len(hp) > 1 else 443
                elif ":" in target:
                    raw_host, pstr = target.rsplit(":", 1)
                    port = int(pstr)
                else:
                    raw_host, port = target, 443
            except ValueError:
                send_err(client, 400, "Invalid CONNECT target\n")
                return

            host = normalize_host(raw_host)
            if not is_valid_host(host) or not (1 <= port <= 65535):
                send_err(client, 400, "Invalid CONNECT host or port\n")
                return

            if is_i2p(host):
                try:
                    handle_i2p_connect(client, host, port, rest)
                except (OSError, ValueError) as e:
                    send_err(client, 502, f"I2P proxy error: {e}\n")
                return

            if is_private_ip(host):
                send_err(client, 403, "Blocked local/private address\n")
                return

            try:
                up = socks5_connect(host, port)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if rest:
                    up.sendall(rest)
                relay(client, up)
                up.close()
            except (OSError, ValueError) as e:
                send_err(client, 502, f"Nym Mixnet unavailable (fail-closed): {e}\n")
            return

        if method not in ALLOWED_METHODS:
            send_err(client, 400, "Unsupported HTTP method\n")
            return

        # Plain HTTP request
        parsed = urlsplit(target)
        raw_host = parsed.hostname or ""
        try:
            port = parsed.port or 80
        except ValueError:
            send_err(client, 400, "Invalid port\n")
            return

        host_headers = [
            ln.split(b":", 1)[1].strip().decode("latin1")
            for ln in lines[1:]
            if ln.lower().startswith(b"host:")
        ]
        if len(host_headers) > 1:
            send_err(client, 400, "Duplicate Host header\n")
            return
        if not raw_host and host_headers:
            hval = host_headers[0]
            raw_host = hval.split(":", 1)[0]

        host = normalize_host(raw_host)
        if not is_valid_host(host) or not (1 <= port <= 65535):
            send_err(client, 403, "Blocked invalid or local address\n")
            return

        host_authority = f"{host}:{port}" if port != 80 else host
        path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
        if any(ch in path for ch in ("\r", "\n", " ", "\t", "\x00")):
            send_err(client, 400, "Invalid request path\n")
            return

        if is_i2p(host):
            abs_i2p = f"http://{host_authority}{path}"
            i2p_req_line = f"{method} {abs_i2p} {version}".encode("latin1")
            scrubbed = (
                b"\r\n".join(scrub_http_request(lines, host, host_authority, i2p_req_line))
                + b"\r\n\r\n"
                + rest
            )
            try:
                up = socket.create_connection((I2P_HOST, I2P_PORT), timeout=30.0)
                up.settimeout(300.0)
                up.sendall(scrubbed)
                relay(client, up)
                up.close()
            except OSError as e:
                send_err(client, 502, f"I2P proxy error: {e}\n")
            return

        if is_private_ip(host):
            send_err(client, 403, "Blocked local/private address\n")
            return

        req_line = f"{method} {path} {version}".encode("latin1")
        payload = (
            b"\r\n".join(scrub_http_request(lines, host, host_authority, req_line))
            + b"\r\n\r\n"
            + rest
        )

        try:
            up = socks5_connect(host, port)
            up.sendall(payload)
            relay(client, up)
            up.close()
        except (OSError, ValueError) as e:
            send_err(client, 502, f"Nym Mixnet unavailable (fail-closed): {e}\n")


class ThreadedProxy(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    print(f"Mesh Hybrid Router (.i2p->4444, clearnet->1080) on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    with ThreadedProxy((LISTEN_HOST, LISTEN_PORT), ProxyHandler) as srv:
        srv.serve_forever()
