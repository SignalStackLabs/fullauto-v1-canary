# Full Auto v1 Canary

Minimal Python repository used for the first Full Auto v1 end-to-end software-factory canary.

## Usage

Summarize a UTF-8 text file as deterministic JSON:

```powershell
python -m fullauto_canary summarize <path>
```

Output fields, always in this order:

- `lines`: number of lines (`\n`, `\r\n` and `\r` all end a line; a trailing newline does not add a line)
- `non_empty_lines`: lines containing at least one non-whitespace character
- `words`: whitespace-separated tokens
- `characters`: Unicode code points in the decoded text (a leading UTF-8 byte-order mark counts as one character)
- `sha256`: hex SHA-256 of the file's raw bytes

An empty file reports zeros for every count. A missing, unreadable or non-UTF-8 file prints an `error:` message to stderr and exits with status 1.

Example, for a file `notes.txt` containing `Hello world`, a blank line and `Full Auto canary`, each of the three lines ending with a single `\n` (LF):

```text
> python -m fullauto_canary summarize notes.txt
{"lines": 3, "non_empty_lines": 2, "words": 5, "characters": 30, "sha256": "7c14d498a3353bb853a5e2c348de7e4c206d7a90c8331331b0316f810f715fda"}
```

## Tests

```powershell
python -m unittest discover -s tests -v
```
