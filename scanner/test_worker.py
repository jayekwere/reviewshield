from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from typing import Any
from unittest.mock import patch

from scanner.worker import scan_checkout, scan_manifest


class WorkerTests(unittest.TestCase):
    def test_manifest_transfer_keeps_private_source_and_checks_digest(self) -> None:
        data = b"pass\n"
        manifest = {
            "schema_version": "1.0",
            "files": [
                {
                    "path": "nested/file.py",
                    "content_base64": base64.b64encode(data).decode(),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            ],
        }

        def scan(root: Path, rules: Path) -> dict[str, Any]:
            source = root / "nested/file.py"
            self.assertEqual(source.read_bytes(), data)
            self.assertEqual(source.stat().st_mode & 0o777, 0o600)
            return {"verified": True}

        with patch("scanner.worker.scan_checkout", side_effect=scan):
            self.assertEqual(
                scan_manifest(json.dumps(manifest).encode(), Path("policy/semgrep.yml")),
                {"verified": True},
            )

    def test_manifest_rejects_paths_duplicates_substitution_and_invalid_encoding(self) -> None:
        file = {
            "path": "file.py",
            "content_base64": "cGFzcwo=",
            "sha256": hashlib.sha256(b"pass\n").hexdigest(),
        }
        for item in [
            dict(file, path=p)
            for p in [
                "/outside.py",
                "../outside.py",
                "a/../outside.py",
                "a\\file.py",
                "a//file.py",
                "a.py%00",
                "a.ts",
            ]
        ] + [dict(file, sha256="0" * 64), dict(file, content_base64="%%%=")]:
            with self.assertRaises(ValueError):
                scan_manifest(
                    json.dumps({"schema_version": "1.0", "files": [item]}).encode(),
                    Path("policy/semgrep.yml"),
                )
        for files in [[], [file, file]]:
            with self.assertRaises(ValueError):
                scan_manifest(
                    json.dumps({"schema_version": "1.0", "files": files}).encode(),
                    Path("policy/semgrep.yml"),
                )
        with self.assertRaises(ValueError):
            scan_manifest(b" " * 12_000_001, Path("policy/semgrep.yml"))

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
