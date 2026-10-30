from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from typing import Any
from unittest.mock import patch

from scanner.worker import scan_checkout


class WorkerTests(unittest.TestCase):
    def test_native_coverage_and_source_digest_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "file.py").write_text("pass\n")
            (root / ".semgrepignore").write_text("*.py\n")

            def native(args: list[str], **kwargs: object) -> CompletedProcess[str]:
                snapshot = Path(args[-1])
                self.assertFalse((snapshot / ".semgrepignore").exists())
                self.assertEqual(kwargs["cwd"], snapshot)
                self.assertNotIn("shell", kwargs)
                Path(args[args.index("--sarif-output") + 1]).write_text(
                    json.dumps({"version": "2.1.0", "runs": [{"results": []}]})
                )
                return CompletedProcess(
                    args,
                    0,
                    json.dumps({"paths": {"scanned": [str(snapshot / "file.py")]}, "errors": []}),
                    "",
                )

            with patch("scanner.worker.subprocess.run", side_effect=native):
                result = scan_checkout(root, Path("policy/semgrep.yml"))
            self.assertEqual(result["coverage"]["expected"], ["file.py"])
            self.assertEqual(result["coverage"]["native_scanned"], ["file.py"])
            self.assertEqual(len(result["files"]["file.py"]), 64)
            self.assertEqual(result["scope"], "configured-python-rules")

    def test_skipped_file_or_parser_error_cannot_be_clean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "file.py").write_text("pass\n")
            reports: list[dict[str, Any]] = [
                {"paths": {"scanned": []}, "errors": []},
                {"paths": {"scanned": []}, "errors": [{"type": "ParseError"}]},
            ]
            for report in reports:

                def native(
                    args: list[str], report: dict[str, Any] = report, **kwargs: object
                ) -> CompletedProcess[str]:
                    Path(args[args.index("--sarif-output") + 1]).write_text("{}")
                    return CompletedProcess(args, 0, json.dumps(report), "")

                with (
                    patch("scanner.worker.subprocess.run", side_effect=native),
                    self.assertRaises(RuntimeError),
                ):
                    scan_checkout(root, Path("policy/semgrep.yml"))

    def test_symlink_large_file_and_empty_scope_reject_before_scanning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError):
                scan_checkout(root, Path("policy/semgrep.yml"))
            (root / "file.py").write_bytes(b"x" * 1_000_001)
            with self.assertRaises(ValueError):
                scan_checkout(root, Path("policy/semgrep.yml"))
            (root / "file.py").unlink()
            (root / "file.py").symlink_to("/etc/passwd")
            with self.assertRaises(ValueError):
                scan_checkout(root, Path("policy/semgrep.yml"))

    def test_nonzero_native_exit_is_not_a_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "file.py").write_text("pass\n")
            with (
                patch(
                    "scanner.worker.subprocess.run",
                    return_value=CompletedProcess([], 2, "{}", "private failure"),
                ),
                self.assertRaises(RuntimeError),
            ):
                scan_checkout(root, Path("policy/semgrep.yml"))


if __name__ == "__main__":
    unittest.main()
