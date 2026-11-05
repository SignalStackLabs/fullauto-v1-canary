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

    def test_a_token_is_required_to_start(self):
        with self.assertRaises(ValueError):
            make_server(0, self.tmp.name, "", "v")


if __name__ == "__main__":
    unittest.main()
