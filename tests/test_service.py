import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from fullauto_canary.service import MAX_TEXT, make_server

TOKEN = "test-token"


class ServiceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.srv = make_server(0, self.tmp.name, TOKEN, "abc123")
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.tmp.cleanup()

    def call(self, method, path, body=None, token=TOKEN, raw=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req) as r:
                text = r.read()
                return r.status, json.loads(text) if text else None
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    def test_health_reports_version(self):
        self.assertEqual(self.call("GET", "/health", token=None), (200, {"status": "ok", "version": "abc123", "notes": 0}))

    def test_create_list_get_delete(self):
        code, note = self.call("POST", "/api/notes", {"text": "  first  "})
        self.assertEqual((code, note), (201, {"id": 1, "text": "first"}))
        self.assertEqual(self.call("GET", "/api/notes", token=None), (200, [note]))
        self.assertEqual(self.call("GET", "/api/notes/1", token=None), (200, note))
        self.assertEqual(self.call("DELETE", "/api/notes/1"), (204, None))
        self.assertEqual(self.call("GET", "/api/notes/1", token=None)[0], 404)

    def test_writes_require_the_token(self):
        self.assertEqual(self.call("POST", "/api/notes", {"text": "x"}, token=None)[0], 401)
        self.assertEqual(self.call("POST", "/api/notes", {"text": "x"}, token="wrong")[0], 401)
        self.call("POST", "/api/notes", {"text": "x"})
        self.assertEqual(self.call("DELETE", "/api/notes/1", token=None)[0], 401)
        self.assertEqual(self.call("GET", "/api/notes", token=None)[1], [{"id": 1, "text": "x"}])

    def test_invalid_input(self):
        self.assertEqual(self.call("POST", "/api/notes", raw=b"{not json")[0], 400)
        self.assertEqual(self.call("POST", "/api/notes", {"text": ""})[0], 400)
        self.assertEqual(self.call("POST", "/api/notes", {"text": "x" * (MAX_TEXT + 1)})[0], 400)
        self.assertEqual(self.call("POST", "/api/notes", ["text"])[0], 400)
        self.assertEqual(self.call("POST", "/api/notes", raw=b"x" * 5000)[0], 413)

    def test_unknown_paths_and_methods(self):
        self.assertEqual(self.call("GET", "/nope", token=None)[0], 404)
        self.assertEqual(self.call("DELETE", "/api/notes/99")[0], 404)
        self.assertEqual(self.call("PUT", "/api/notes")[0], 405)
        self.assertEqual(self.call("POST", "/health")[0], 405)

    def test_notes_survive_a_restart(self):
        self.call("POST", "/api/notes", {"text": "kept"})
        self.srv.shutdown()
        self.srv.server_close()
        self.srv = make_server(0, self.tmp.name, TOKEN, "def456")
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.assertEqual(self.call("GET", "/api/notes", token=None), (200, [{"id": 1, "text": "kept"}]))
        self.assertEqual(self.call("POST", "/api/notes", {"text": "next"})[1]["id"], 2)

    def raw(self, request: bytes):
        import socket
        with socket.create_connection(("127.0.0.1", self.srv.server_address[1]), timeout=5) as s:
            s.sendall(request)
            chunks = []
            while True:                      # the server closes the connection after this error
                c = s.recv(4096)
                if not c:
                    return b"".join(chunks).decode("latin-1")
                chunks.append(c)

    def test_extension_methods_get_json_405_with_allow(self):
        resp = self.raw(b"PROPFIND /api/notes HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertTrue(resp.startswith("HTTP/1.0 405"), resp)
        self.assertIn("Allow: GET, POST", resp)
        self.assertIn('{"error": "method not allowed"}', resp)
        resp = self.raw(b"COPY /nope HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertTrue(resp.startswith("HTTP/1.0 404"), resp)

    def test_non_ascii_digits_are_rejected_not_crashing(self):
        resp = self.raw(b"POST /api/notes HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + TOKEN.encode()
                        + "\r\nContent-Length: ²\r\n\r\n".encode("latin-1"))
        self.assertIn('"error": "invalid Content-Length"', resp)
        self.assertEqual(self.call("GET", "/api/notes/%C2%B2", token=None)[0], 404)
        self.assertEqual(self.call("GET", "/api/notes/" + "9" * 30, token=None)[0], 404)

    def test_rejected_writes_close_the_connection(self):
        resp = self.raw(b"POST /api/notes HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}")   # no token -> 401
        self.assertTrue(resp.startswith("HTTP/1.0 401"), resp)
        self.assertIn("Connection: close", resp)

    def test_malformed_content_length_gets_a_json_400(self):
        for value in (b"abc", b"-1", b"1.5"):
            resp = self.raw(b"POST /api/notes HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + TOKEN.encode()
                            + b"\r\nContent-Length: " + value + b"\r\n\r\n")
            self.assertTrue(resp.startswith("HTTP/1.0 400") or resp.startswith("HTTP/1.1 400"), resp)
            self.assertIn('"error": "invalid Content-Length"', resp)

    def test_other_methods_get_json_405_or_404(self):
        for method in ("OPTIONS", "TRACE", "PATCH"):
            code, body = self.call(method, "/api/notes")
            self.assertEqual((code, body), (405, {"error": "method not allowed"}), method)
        self.assertEqual(self.call("OPTIONS", "/nope")[0], 404)
        req = urllib.request.Request(self.base + "/health", method="HEAD")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 405)
        self.assertEqual(cm.exception.read(), b"")

    def test_length_limit_applies_after_trimming(self):
        code, note = self.call("POST", "/api/notes", {"text": "  " + "y" * MAX_TEXT + "  "})
        self.assertEqual((code, len(note["text"])), (201, MAX_TEXT))

    def test_any_declared_length_over_the_limit_is_413_and_zero_padding_is_valid(self):
        for value in (b"4097", b"1000000000", b"9" * 25):
            resp = self.raw(b"POST /api/notes HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + TOKEN.encode()
                            + b"\r\nContent-Length: " + value + b"\r\n\r\n")
            self.assertTrue(resp.startswith("HTTP/1.0 413"), (value, resp))
        body = b'{"text": "padded"}'
        resp = self.raw(b"POST /api/notes HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + TOKEN.encode()
                        + b"\r\nContent-Length: 000000" + str(len(body)).encode() + b"\r\n\r\n" + body)
        self.assertTrue(resp.startswith("HTTP/1.0 201"), resp)

    def test_a_stalled_body_gets_408_and_does_not_pin_the_handler(self):
        import socket, time
        self.srv.shutdown()
        self.srv.server_close()
        self.srv = make_server(0, self.tmp.name, TOKEN, "abc123", read_timeout=0.5)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        t0 = time.monotonic()
        with socket.create_connection(("127.0.0.1", self.srv.server_address[1]), timeout=5) as s:
            s.sendall(b"POST /api/notes HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + TOKEN.encode()
                      + b"\r\nContent-Length: 100\r\n\r\n{\"te")
            resp = b""
            while True:
                c = s.recv(4096)
                if not c:
                    break
                resp += c
        self.assertTrue(resp.startswith(b"HTTP/1.0 408"), resp)
        self.assertLess(time.monotonic() - t0, 4)
        self.assertEqual(self.call("GET", "/api/notes", token=None), (200, []))

    def _short_timeout_server(self, seconds):
        self.srv.shutdown()
        self.srv.server_close()
        self.srv = make_server(0, self.tmp.name, TOKEN, "abc123", read_timeout=seconds)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def test_a_truncated_body_with_half_close_is_rejected_and_writes_nothing(self):
        import socket
        with socket.create_connection(("127.0.0.1", self.srv.server_address[1]), timeout=5) as s:
            s.sendall(b"POST /api/notes HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + TOKEN.encode()
                      + b'\r\nContent-Length: 100\r\n\r\n{"text": "partial"}')
            s.shutdown(socket.SHUT_WR)
            resp = b""
            while True:
                c = s.recv(4096)
                if not c:
                    break
                resp += c
        self.assertTrue(resp.startswith(b"HTTP/1.0 400"), resp)
        self.assertIn(b"shorter than Content-Length", resp)
        self.assertEqual(self.call("GET", "/api/notes", token=None), (200, []))

    def test_a_dripping_body_hits_one_total_deadline(self):
        import socket, time
        self._short_timeout_server(1.0)
        t0 = time.monotonic()
        with socket.create_connection(("127.0.0.1", self.srv.server_address[1]), timeout=10) as s:
            s.sendall(b"POST /api/notes HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + TOKEN.encode()
                      + b"\r\nContent-Length: 50\r\n\r\n")
            resp = b""
            for _ in range(20):                     # one byte every 0.3 s: each read is under the 1 s timeout
                try:
                    s.sendall(b" ")
                except OSError:
                    break
                time.sleep(0.3)
                s.setblocking(False)
                try:
                    resp += s.recv(4096)
                except (BlockingIOError, OSError):
                    pass
                s.setblocking(True)
                if resp:
                    break
        self.assertTrue(resp.startswith(b"HTTP/1.0 408"), resp)
        self.assertLess(time.monotonic() - t0, 4)

    def test_a_byte_just_before_the_deadline_cannot_extend_it(self):
        import socket, time
        self._short_timeout_server(1.0)
        with socket.create_connection(("127.0.0.1", self.srv.server_address[1]), timeout=10) as s:
            s.sendall(b"POST /api/notes HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + TOKEN.encode()
                      + b"\r\nContent-Length: 50\r\n\r\n")
            time.sleep(0.9)
            t0 = time.monotonic()
            s.sendall(b" ")                         # arrives ~0.1 s before the body deadline
            resp = b""
            while True:
                c = s.recv(4096)
                if not c:
                    break
                resp += c
        self.assertTrue(resp.startswith(b"HTTP/1.0 408"), resp)
        self.assertLess(time.monotonic() - t0, 0.8)  # not a further full 1 s read

    def test_a_token_is_required_to_start(self):
        with self.assertRaises(ValueError):
            make_server(0, self.tmp.name, "", "v")


if __name__ == "__main__":
    unittest.main()
