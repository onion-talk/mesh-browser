import http.client
import importlib.util
import json
import os
import re
import socket
import socketserver
import tempfile
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_mod(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeI2pdHandler(socketserver.BaseRequestHandler):
    """Simulates i2pd HTTP proxy (:4444) where port-80 absolute-form succeeds and CONNECT :443 drops."""
    last_request = b""

    def handle(self):
        data = b""
        while b"\r\n\r\n" not in data:
            c = self.request.recv(4096)
            if not c:
                return
            data += c
        FakeI2pdHandler.last_request = data
        first = data.split(b"\r\n", 1)[0]
        if first.startswith(b"CONNECT ") and b":443 " in first:
            # Simulate an I2P server tunnel that only listens on port 80 unless TLS is used
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            peek = self.request.recv(5)
            if peek and peek[0] == 0x16:
                self.request.sendall(b"\x16\x03\x03\x00\x02ok")
            return
        if first.startswith(b"GET http://planet.i2p/ "):
            body = b"<html><title>Planet I2P</title><body>ok</body></html>"
            hdr = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html\r\n"
                + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            )
            self.request.sendall(hdr + body)
            return
        self.request.sendall(b"HTTP/1.1 502 Unexpected\r\nConnection: close\r\n\r\n")


class MeshSecurityAndRouterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.router = load_mod("mesh_router", "mesh-router.py")
        cls.srv = load_mod("mesh_server", "server.py")
        cls.vplug = load_mod("vnc_token_plugin", "vnc_token_plugin.py")

        cls.i2pd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), FakeI2pdHandler)
        cls.i2pd_port = cls.i2pd.server_address[1]
        threading.Thread(target=cls.i2pd.serve_forever, daemon=True).start()

        cls.router.I2P_PORT = cls.i2pd_port
        cls.r_srv = cls.router.ThreadedProxy(("127.0.0.1", 0), cls.router.ProxyHandler)
        cls.r_port = cls.r_srv.server_address[1]
        threading.Thread(target=cls.r_srv.serve_forever, daemon=True).start()

        cls.c_srv = cls.srv.ReusableTCPServer(("127.0.0.1", 0), cls.srv.Handler)
        cls.c_port = cls.c_srv.server_address[1]
        cls.srv.ALLOWED_HOSTS.add(f"127.0.0.1:{cls.c_port}")
        cls.srv.ALLOWED_ORIGINS.add(f"http://127.0.0.1:{cls.c_port}")
        threading.Thread(target=cls.c_srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.c_srv.shutdown()
        cls.c_srv.server_close()
        cls.r_srv.shutdown()
        cls.r_srv.server_close()
        cls.i2pd.shutdown()
        cls.i2pd.server_close()

    def test_servo_http_inside_connect_443_demuxed_to_port_80(self):
        with socket.create_connection(("127.0.0.1", self.r_port), timeout=5) as s:
            s.sendall(b"CONNECT planet.i2p:443 HTTP/1.1\r\nHost: planet.i2p:443\r\n\r\n")
            resp = s.recv(1024)
            self.assertIn(b"200 Connection Established", resp)
            s.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host: planet.i2p\r\n"
                b"Referer: https://tracker.example/leak\r\n"
                b"Accept-Language: pt-BR\r\n\r\n"
            )
            page = b""
            while True:
                c = s.recv(4096)
                if not c:
                    break
                page += c
        self.assertIn(b"HTTP/1.1 200 OK", page)
        self.assertIn(b"Planet I2P", page)
        self.assertIn(b"GET http://planet.i2p/ HTTP/1.1", FakeI2pdHandler.last_request)
        self.assertNotIn(b"tracker.example", FakeI2pdHandler.last_request)
        self.assertIn(b"Accept-Language: en-US,en;q=0.5", FakeI2pdHandler.last_request)

    def test_genuine_tls_connect_preserved(self):
        with socket.create_connection(("127.0.0.1", self.r_port), timeout=5) as s:
            s.sendall(b"CONNECT planet.i2p:443 HTTP/1.1\r\nHost: planet.i2p:443\r\n\r\n")
            self.assertIn(b"200", s.recv(1024))
            s.sendall(b"\x16\x03\x01\x00\x05hello")
            tls_reply = s.recv(1024)
            self.assertTrue(tls_reply.startswith(b"\x16\x03\x03"))

    def test_private_ip_blocked_fail_closed(self):
        for target, host in (
            ("http://192.168.3.1/", "192.168.3.1"),
            ("http://127.0.0.1:8080/", "127.0.0.1"),
            ("http://localhost/", "localhost"),
            ("http://sub.localhost./", "sub.localhost."),
            ("http://100.64.0.1/", "100.64.0.1"),
        ):
            with socket.create_connection(("127.0.0.1", self.r_port), timeout=5) as s:
                s.sendall(f"GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
                reply = s.recv(1024)
                self.assertIn(b"403", reply)

    def test_connect_authority_override_and_smuggling_blocked(self):
        # 1. Authority override inside CONNECT .i2p (attempting to reach 127.0.0.1:7070)
        FakeI2pdHandler.last_request = b""
        with socket.create_connection(("127.0.0.1", self.r_port), timeout=5) as s:
            s.sendall(b"CONNECT planet.i2p:443 HTTP/1.1\r\nHost: planet.i2p:443\r\n\r\n")
            self.assertIn(b"200", s.recv(1024))
            s.sendall(b"GET http://127.0.0.1:7070/ HTTP/1.1\r\nHost: 127.0.0.1:7070\r\n\r\n")
            reply = s.recv(1024)
            self.assertIn(b"403", reply)
        self.assertEqual(FakeI2pdHandler.last_request, b"")

        # 2. Bare LF / HTAB injection in CONNECT target
        with socket.create_connection(("127.0.0.1", self.r_port), timeout=5) as s:
            s.sendall(b"CONNECT evil\t.i2p:443 HTTP/1.1\r\nHost: planet.i2p:443\r\n\r\n")
            reply = s.recv(1024)
            self.assertIn(b"400", reply)

        # 3. CL + TE smuggling rejected
        with socket.create_connection(("127.0.0.1", self.r_port), timeout=5) as s:
            s.sendall(
                b"POST http://planet.i2p/ HTTP/1.1\r\n"
                b"Host: planet.i2p\r\n"
                b"Content-Length: 4\r\n"
                b"Transfer-Encoding: chunked\r\n\r\n"
            )
            reply = s.recv(1024)
            self.assertIn(b"400", reply)

    def test_vnc_token_plugin_blocks_path_traversal(self):
        with tempfile.TemporaryDirectory() as d:
            plug = self.vplug.SafeUnixSocketDirectory(d)
            for bad in (
                "../../run/user/1000/bus",
                "../other/0123456789abcdef0123456789abcdef",
                "not-hex",
                "0123456789abcdef",
                "",
            ):
                self.assertIsNone(plug.lookup(bad))
            if hasattr(socket, "AF_UNIX"):
                valid_tok = "a" * 32
                sock_path = os.path.join(d, valid_tok)
                srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    srv.bind(sock_path)
                    res = plug.lookup(valid_tok)
                    self.assertIsNotNone(res)
                    self.assertEqual(res[0], "unix_socket")
                finally:
                    srv.close()
                    if os.path.exists(sock_path):
                        os.remove(sock_path)

    def test_dns_rebinding_host_rejected(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.c_port, timeout=5)
        conn.putrequest("GET", "/ui.html", skip_host=True)
        conn.putheader("Host", "attacker-rebind.example:8080")
        conn.endheaders()
        r = conn.getresponse()
        self.assertEqual(r.status, 403)
        conn.close()

    def test_csrf_and_method_enforcement(self):
        # 1. Fetch UI to extract session token
        conn = http.client.HTTPConnection("127.0.0.1", self.c_port, timeout=5)
        conn.request("GET", "/")
        r = conn.getresponse()
        html = r.read().decode("utf-8")
        self.assertEqual(r.status, 200)
        m = re.search(r'window\.__MESH_TOKEN__="([^"]+)"', html)
        self.assertIsNotNone(m)
        tok = m.group(1)

        # 2. Arbitrary directory / source file access blocked
        for secret_path in ("/server.py", "/.clean-share/secret.txt", "/mesh-prefs.json"):
            conn.request("GET", secret_path)
            self.assertEqual(conn.getresponse().status, 404)
            conn.close()
            conn = http.client.HTTPConnection("127.0.0.1", self.c_port, timeout=5)

        # 3. GET mutation rejected with 405
        conn.request("GET", "/api/config?level=safest", headers={"X-Mesh-Token": tok})
        self.assertEqual(conn.getresponse().status, 405)
        conn.close()

        # 4. POST mutation without token rejected with 403
        conn = http.client.HTTPConnection("127.0.0.1", self.c_port, timeout=5)
        conn.request("POST", "/api/config", body=json.dumps({"level": "safest"}), headers={"Content-Type": "application/json"})
        self.assertEqual(conn.getresponse().status, 403)
        conn.close()

        # 5. Authenticated GET /api/status succeeds
        conn = http.client.HTTPConnection("127.0.0.1", self.c_port, timeout=5)
        conn.request("GET", "/api/status", headers={"X-Mesh-Token": tok})
        sr = conn.getresponse()
        self.assertEqual(sr.status, 200)
        data = json.loads(sr.read().decode("utf-8"))
        self.assertIn("i2p", data)
        self.assertIn("nym", data)
        self.assertIn("router", data)
        conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
