import json
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from scanner.scan import normalize_locations, scan


class ScannerTests(unittest.TestCase):
    def test_absolute_paths_must_resolve_inside_the_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "file.py"
            source.write_text("pass\n")
            artifact = {"uri": str(source)}
            report = {
                "runs": [
                    {
                        "results": [
                            {"locations": [{"physicalLocation": {"artifactLocation": artifact}}]}
                        ]
                    }
                ]
            }
            normalize_locations(report, root)
            self.assertEqual(artifact["uri"], "file.py")
            for unsafe in [
                str(root.parent / "outside.py"),
                "https://example.invalid/file.py",
                "../outside.py",
            ]:
                artifact["uri"] = unsafe
                with self.assertRaises(ValueError):
                    normalize_locations(report, root)

    def test_success_provenance_and_no_shell(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            with patch(
                "scanner.scan.subprocess.run",
                return_value=CompletedProcess([], 0, json.dumps({"runs": [{}]}), ""),
            ) as run:
                scan(Path("fixtures"), Path("policy/semgrep.yml"), output)
            self.assertTrue(
                json.loads(output.read_text())["runs"][0]["invocations"][0]["executionSuccessful"]
            )
            self.assertNotIn("shell", run.call_args.kwargs)
            self.assertEqual(run.call_args.kwargs["timeout"], 120)

    def test_failed_scanner_is_never_a_clean_report(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "scanner.scan.subprocess.run", return_value=CompletedProcess([], 2, "{}", "error")
            ),
        ):
            with self.assertRaises(RuntimeError):
                scan(Path("fixtures"), Path("policy/semgrep.yml"), Path(directory) / "report.json")


if __name__ == "__main__":
    unittest.main()
