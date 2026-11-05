"""Canary notes service: a small HTTP JSON API used as Full Auto's deployment target.

Run:  python -m fullauto_canary.service --port 8765 --data-dir DIR --token-file FILE [--version SHA]
Binds to 127.0.0.1 only.

Endpoints
  GET    /health            {"status": "ok", "version": <deployed commit>, "notes": <count>}
  GET    /api/notes         list of notes (public)
  GET    /api/notes/<id>    one note, 404 if absent (public)
  POST   /api/notes         {"text": "..."} -> 201 + note        (requires Authorization: Bearer <token>)
  DELETE /api/notes/<id>    204, 404 if absent                    (requires Authorization: Bearer <token>)
Errors are JSON {"error": "..."}: 400 invalid body or Content-Length, 401 missing/wrong token, 404 unknown path or id,
405 any other method on a known path (HEAD responses carry no body), 413 body over 4 KiB.
Text is trimmed before the 1-280 character check.
Notes persist in <data-dir>/notes.json (written atomically), so they survive a redeploy.
"""
import argparse, hmac, json, os, re, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 4096
MAX_TEXT = 280
ASCII_INT = re.compile(r"[0-9]{1,9}")         # ASCII digits only: str.isdigit() also accepts e.g. "²", which int() rejects
ALLOW = {"health": "GET", "notes": "GET, POST", "note": "GET, DELETE"}


class Store:
    def __init__(self, data_dir):
        self.path = os.path.join(data_dir, "notes.json")
        self.lock = threading.Lock()
        os.makedirs(data_dir, exist_ok=True)
        if not os.path.exists(self.path):
            self._write({"next_id": 1, "notes": []})

    def _read(self):
        with open(self.path, encoding="utf-8") as f:
            return json.load(f)

    def _write(self, state):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f)
        os.replace(tmp, self.path)

    def list(self):
        with self.lock:
            return self._read()["notes"]

    def get(self, note_id):
        return next((n for n in self.list() if n["id"] == note_id), None)

    def add(self, text):
        with self.lock:
            state = self._read()
            note = {"id": state["next_id"], "text": text}
            state["next_id"] += 1
            state["notes"].append(note)
            self._write(state)
            return note

    def delete(self, note_id):
        with self.lock:
            state = self._read()
            keep = [n for n in state["notes"] if n["id"] != note_id]
            if len(keep) == len(state["notes"]):
                return False
            state["notes"] = keep
            self._write(state)
            return True


def make_handler(store, token, version):
    class Handler(BaseHTTPRequestHandler):
        server_version = "fullauto-canary"

        def log_message(self, fmt, *args):  # quiet
            pass

        def __getattr__(self, name):
            # Any HTTP method without its own do_* handler (PUT, PROPFIND, ...) gets the JSON 405/404 contract
            # instead of BaseHTTPRequestHandler's HTML 501.
            if name.startswith("do_"):
                return self._unsupported
            raise AttributeError(name)

        def _send(self, code, body=None):
            data = b"" if body is None else json.dumps(body).encode("utf-8")
            closing = code >= 400 and self.command != "GET"   # an unread request body must not desync keep-alive
            self.send_response(code)
            if closing:
                self.send_header("Connection", "close")       # also sets close_connection
                self.close_connection = True
            if code == 405:
                self.send_header("Allow", ALLOW[self._route()])
            if body is not None:
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def _authorized(self):
            got = self.headers.get("Authorization", "")
            return got.startswith("Bearer ") and hmac.compare_digest(got[7:].encode(), token.encode())

        def _note_id(self):
            parts = self.path.split("?", 1)[0].rstrip("/").split("/")
            if len(parts) == 4 and parts[1:3] == ["api", "notes"]:
                return int(parts[3]) if ASCII_INT.fullmatch(parts[3]) else -1
            return None

        def _route(self):
            p = self.path.split("?", 1)[0].rstrip("/")
            if p == "/health":
                return "health"
            if p == "/api/notes":
                return "notes"
            if self._note_id() is not None:
                return "note"
            return None

        def do_GET(self):
            r = self._route()
            if r == "health":
                return self._send(200, {"status": "ok", "version": version, "notes": len(store.list())})
            if r == "notes":
                return self._send(200, store.list())
            if r == "note":
                n = store.get(self._note_id())
                return self._send(200, n) if n else self._send(404, {"error": "note not found"})
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            r = self._route()
            if r is None:
                return self._send(404, {"error": "not found"})
            if r != "notes":
                return self._send(405, {"error": "method not allowed"})
            if not self._authorized():
                return self._send(401, {"error": "unauthorized"})
            raw_length = (self.headers.get("Content-Length") or "0").strip()
            if not ASCII_INT.fullmatch(raw_length):
                return self._send(400, {"error": "invalid Content-Length"})
            length = int(raw_length)
            if length > MAX_BODY:
                return self._send(413, {"error": "body too large"})
            try:
                body = json.loads(self.rfile.read(length) or b"null")
            except (ValueError, UnicodeDecodeError):
                return self._send(400, {"error": "invalid JSON"})
            text = body.get("text") if isinstance(body, dict) else None
            text = text.strip() if isinstance(text, str) else ""
            if not text or len(text) > MAX_TEXT:
                return self._send(400, {"error": f"text must be a non-empty string of at most {MAX_TEXT} characters"})
            return self._send(201, store.add(text))

        def do_DELETE(self):
            r = self._route()
            if r is None:
                return self._send(404, {"error": "not found"})
            if r != "note":
                return self._send(405, {"error": "method not allowed"})
            if not self._authorized():
                return self._send(401, {"error": "unauthorized"})
            return self._send(204) if store.delete(self._note_id()) else self._send(404, {"error": "note not found"})

        def _unsupported(self):
            if self._route():
                return self._send(405, {"error": "method not allowed"})
            return self._send(404, {"error": "not found"})

        do_HEAD = _unsupported               # explicit: BaseHTTPRequestHandler special-cases HEAD bodies

    return Handler


def make_server(port, data_dir, token, version):
    if not token:
        raise ValueError("an API token is required")
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler(Store(data_dir), token, version))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Canary notes service")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--token-file", required=True)
    ap.add_argument("--version", default="dev")
    a = ap.parse_args(argv)
    with open(a.token_file, encoding="utf-8") as f:
        token = f.read().strip()
    srv = make_server(a.port, a.data_dir, token, a.version)
    try:
        srv.serve_forever()
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
