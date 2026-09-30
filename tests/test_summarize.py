import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

from fullauto_canary.__main__ import main

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestSummarize(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _write(self, data: bytes) -> str:
        path = os.path.join(self._tmp.name, "input.txt")
        with open(path, "wb") as f:
            f.write(data)
        return path

    def _run(self, *argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(list(argv))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_normal_input(self):
        data = b"hello world\n\nfoo bar baz\n"
        code, out, err = self._run("summarize", self._write(data))
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(
            json.loads(out),
            {
                "lines": 3,
                "non_empty_lines": 2,
                "words": 5,
                "characters": 25,
                "sha256": hashlib.sha256(data).hexdigest(),
            },
        )

    def test_output_is_deterministic(self):
        path = self._write(b"a b\nc\n")
        first = self._run("summarize", path)[1]
        second = self._run("summarize", path)[1]
        self.assertEqual(first, second)
        self.assertEqual(
            list(json.loads(first)),
            ["lines", "non_empty_lines", "words", "characters", "sha256"],
        )

    def test_readme_example_exact_output(self):
        code, out, err = self._run("summarize", self._write(b"Hello world\n\nFull Auto canary\n"))
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(
            out,
            '{"lines": 3, "non_empty_lines": 2, "words": 5, "characters": 30, '
            '"sha256": "7c14d498a3353bb853a5e2c348de7e4c206d7a90c8331331b0316f810f715fda"}\n',
        )

    def test_empty_input(self):
        code, out, err = self._run("summarize", self._write(b""))
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(
            json.loads(out),
            {
                "lines": 0,
                "non_empty_lines": 0,
                "words": 0,
                "characters": 0,
                "sha256": hashlib.sha256(b"").hexdigest(),
            },
        )

    def test_unicode_input(self):
        text = "héllo wörld\n日本語 テキスト 🙂"
        data = text.encode("utf-8")
        code, out, err = self._run("summarize", self._write(data))
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(
            json.loads(out),
            {
                "lines": 2,
                "non_empty_lines": 2,
                "words": 5,
                "characters": len(text),
                "sha256": hashlib.sha256(data).hexdigest(),
            },
        )

    def test_missing_file(self):
        path = os.path.join(self._tmp.name, "does-not-exist.txt")
        code, out, err = self._run("summarize", path)
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")
        self.assertIn("error: cannot read", err)
        self.assertIn("does-not-exist.txt", err)

    def test_invalid_utf8(self):
        code, out, err = self._run("summarize", self._write(b"\xff\xfe\x00"))
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")
        self.assertIn("not valid UTF-8", err)

    def test_module_invocation(self):
        path = self._write(b"one two\n")
        result = subprocess.run(
            [sys.executable, "-m", "fullauto_canary", "summarize", path],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["words"], 2)


if __name__ == "__main__":
    unittest.main()
