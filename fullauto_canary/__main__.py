"""Command-line entry point: ``python -m fullauto_canary summarize <path>``."""

import argparse
import hashlib
import json
import sys


def summarize_bytes(data: bytes) -> dict:
    """Return summary statistics for UTF-8 encoded ``data``.

    Raises UnicodeDecodeError if ``data`` is not valid UTF-8.
    """
    text = data.decode("utf-8")
    # Count lines with universal newlines (\n, \r\n, \r); a trailing
    # newline does not start an extra line.
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if lines[-1] == "":
        lines.pop()
    return {
        "lines": len(lines),
        "non_empty_lines": sum(1 for line in lines if line.strip()),
        "words": len(text.split()),
        "characters": len(text),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m fullauto_canary")
    subparsers = parser.add_subparsers(dest="command", required=True)
    summarize = subparsers.add_parser(
        "summarize", help="print JSON statistics for a UTF-8 text file"
    )
    summarize.add_argument("path")
    args = parser.parse_args(argv)

    try:
        with open(args.path, "rb") as f:
            data = f.read()
        summary = summarize_bytes(data)
    except OSError as exc:
        print(f"error: cannot read {args.path!r}: {exc.strerror or exc}", file=sys.stderr)
        return 1
    except UnicodeDecodeError as exc:
        print(f"error: {args.path!r} is not valid UTF-8: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(summary, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
