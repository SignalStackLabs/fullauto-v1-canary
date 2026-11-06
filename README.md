# Full Auto v1 Canary

Minimal Python repository used as Full Auto's disposable end-to-end canary: missions are implemented here, delivered
through GitHub (CI, PR, merge) and deployed to an isolated local environment.

## Notes service

A small HTTP JSON API (standard library only), bound to 127.0.0.1:

```powershell
python -m fullauto_canary.service --port 8765 --data-dir <dir> --token-file <file> --version <sha>
```

| Method | Path | Auth | Result |
|---|---|---|---|
| GET | `/health` | none | `{"status": "ok", "version": ..., "notes": n}` |
| GET | `/api/notes` | none | all notes |
| GET | `/api/notes/<id>` | none | one note, 404 if absent |
| POST | `/api/notes` | Bearer token | `{"text": "..."}` (1-280 chars, trimmed) -> 201 + note |
| DELETE | `/api/notes/<id>` | Bearer token | 204, 404 if absent |

Errors are JSON `{"error": ...}`: 400 invalid body or `Content-Length`, 401 missing or wrong token, 404 unknown path or
id, 405 any other method on a known path (`HEAD` responses carry no body), 408 body not received within the 10 s read
timeout, 413 any declared body over 4 KiB. Text is trimmed before the length check. Notes persist in `<data-dir>/notes.json` across restarts and redeploys.

## Tests

```powershell
python -m unittest discover -s tests -v
```

CI (`.github/workflows/ci.yml`) runs the same command on every pull request and on pushes to `main`.
