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
405 any other method on a known path (HEAD responses carry no body), 408 body not received within the read timeout
(10 s), 413 body over 4 KiB (any declared length above it, however many digits).
A note id that is not 1-9 ASCII digits is an unknown path: 404 on every method, before the token check.
Malformed requests get the same JSON shape with a status line: 400 bad request line or version, 414 path too long,
431 header line too long or too many headers, 505 unsupported HTTP version. A 204 response carries no Content-Length.
Text is trimmed before the 1-280 character check.
Notes persist in <data-dir>/notes.json (written atomically), so they survive a redeploy.
"""
import argparse, hmac, json, os, re, socket, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 4096
MAX_TEXT = 280
ASCII_INT = re.compile(r"[0-9]{1,9}")         # ASCII digits only: str.isdigit() also accepts e.g. "²", which int() rejects
ASCII_DIGITS = re.compile(r"[0-9]+")
READ_TIMEOUT = 10.0                           # seconds a connection may stall before it is answered 408 / dropped
ALLOW = {"health": "GET", "notes": "GET, POST", "note": "GET, DELETE"}
# Fixed text for requests the standard library rejects while parsing (stable across Python versions; never echoes input)
MALFORMED_ERRORS = {400: "bad request", 414: "uri too long", 431: "request header fields too large",
                    505: "http version not supported"}


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

        def setup(self):
            # One absolute deadline per connection (HTTP/1.0: one request each), covering the request line, headers
            # and body. A client that drips header bytes under the per-read timeout is still cut off.
            super().setup()
            self._watchdog = threading.Timer(2 * self.timeout, self._cut_off)
            self._watchdog.daemon = True
            self._watchdog.start()

        def _cut_off(self):
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        def handle(self):
            try:
                super().handle()
            except OSError:          # connection cut off by the deadline or by the client: nothing to answer
                self.close_connection = True

        def finish(self):
            self._watchdog.cancel()
            try:
                super().finish()
            except OSError:
                pass

        def __getattr__(self, name):
            # Any HTTP method without its own do_* handler (PUT, PROPFIND, ...) gets the JSON 405/404 contract
            # instead of BaseHTTPRequestHandler's HTML 501.
            if name.startswith("do_"):
                return self._unsupported
            raise AttributeError(name)

        def _send(self, code, body=None, close=False):
            data = b"" if body is None else json.dumps(body).encode("utf-8")
            closing = close or (code >= 400 and self.command != "GET")   # an unread body must not desync keep-alive
            self.send_response(code)
            if closing:
                self.send_header("Connection", "close")       # also sets close_connection
                self.close_connection = True
            if code == 405:
                self.send_header("Allow", ALLOW[self._route()])
            if body is not None:
                self.send_header("Content-Type", "application/json")
            if code != 204:                                    # RFC 9110: a 204 carries no Content-Length
                self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def send_error(self, code, message=None, explain=None):
            # The standard library calls this for requests it cannot parse (400, 414, 431, 505). Answer with the JSON
            # contract instead of its HTML page; message/explain are ignored because they echo request bytes.
            if self.request_version == "HTTP/0.9":   # request line never parsed: still write a status line + headers
                self.request_version = "HTTP/1.0"
            if not self.command:                     # raised before the method was assigned: HEAD must get no body
                words = (getattr(self, "raw_requestline", b"") or b"").split(None, 1)
                self.command = words[0].decode("latin-1") if words else ""
            text = MALFORMED_ERRORS.get(code) or self.responses.get(code, ("error",))[0].lower()
            self._send(code, {"error": text}, close=True)

        def _authorized(self):
            got = self.headers.get("Authorization", "")
            return got.startswith("Bearer ") and hmac.compare_digest(got[7:].encode(), token.encode())

        def _note_id(self):
            parts = self.path.split("?", 1)[0].rstrip("/").split("/")
            if len(parts) == 4 and parts[1:3] == ["api", "notes"] and ASCII_INT.fullmatch(parts[3]):
                return int(parts[3])
            return None                      # any other id can never name a note: an unknown path on every method

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
            declared = self.headers.get_all("Content-Length") or []
            if len(declared) > 1:                                  # ambiguous framing: never pick one
                return self._send(400, {"error": "invalid Content-Length"})
            raw_length = (declared[0] if declared else "0").strip()
            if not ASCII_DIGITS.fullmatch(raw_length):
                return self._send(400, {"error": "invalid Content-Length"})
            significant = raw_length.lstrip("0") or "0"           # zero padding is valid; any length is a number
            if len(significant) > len(str(MAX_BODY)) or int(significant) > MAX_BODY:
                return self._send(413, {"error": "body too large"})
            length, chunks, got = int(significant), [], 0
            deadline = time.monotonic() + self.timeout            # one deadline for the whole body, not per read
            try:
                while got < length:
                    left = deadline - time.monotonic()
                    if left <= 0:
                        raise TimeoutError
                    self.connection.settimeout(left)              # no single read may outlast the body deadline
                    chunk = self.rfile.read1(length - got)
                    if not chunk:                                 # client closed before sending what it declared
                        return self._send(400, {"error": "request body shorter than Content-Length"})
                    chunks.append(chunk)
                    got += len(chunk)
            except TimeoutError:                                  # declared more bytes than it sent in time
                return self._send(408, {"error": "request body not received in time"})
            finally:
                self.connection.settimeout(self.timeout)          # later reads get the normal timeout back
            raw_body = b"".join(chunks)
            try:
                body = json.loads(raw_body or b"null")
            except (ValueError, UnicodeDecodeError, RecursionError):   # RecursionError: deeply nested JSON
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


def make_server(port, data_dir, token, version, read_timeout=READ_TIMEOUT):
    if not token:
        raise ValueError("an API token is required")
    handler = make_handler(Store(data_dir), token, version)
    handler.timeout = read_timeout       # per-connection socket timeout: a stalled client cannot pin a handler thread
    return ThreadingHTTPServer(("127.0.0.1", port), handler)


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
