"""Credential-free Python static scanning with explicit file coverage evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from scanner.scan import normalize_locations


def scan_checkout(root: Path, rules: Path, semgrep: str = "semgrep") -> dict[str, Any]:
    root = root.resolve()
    files: dict[str, str] = {}
    total = 0
    with tempfile.TemporaryDirectory(prefix="reviewshield-input-") as directory:
        copied = (Path(directory) / "source").resolve()
        copied.mkdir()
        for count, path in enumerate(root.rglob("*"), 1):
            if count > 10000 or path.is_symlink():
                raise ValueError("Input exceeds traversal bound or contains a symlink")
            if not path.is_file() or path.suffix != ".py":
                continue
            relative = path.relative_to(root)
            if len(files) >= 500 or path.stat().st_size > 1_000_000:
                raise ValueError("Python source count or file size exceeds scanner scope")
            data = path.read_bytes()
            total += len(data)
            if total > 8_388_608:
                raise ValueError("Python source exceeds 8 MiB")
            destination = copied / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            files[relative.as_posix()] = hashlib.sha256(data).hexdigest()
        if not files:
            raise ValueError("No Python files in the declared scanner scope")
        sarif_path = Path(directory) / "native.sarif"
        result = subprocess.run(
            [
                semgrep,
                "scan",
                "--config",
                str(rules.resolve()),
                "--json",
                "--sarif-output",
                str(sarif_path),
                "--metrics=off",
                "--disable-version-check",
                "--strict",
                "--no-git-ignore",
                "--max-target-bytes=1000000",
                str(copied),
            ],
            cwd=copied,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if (
            result.returncode
            or len(result.stdout) > 8_388_608
            or sarif_path.stat().st_size > 8_388_608
        ):
            raise RuntimeError("Static scanner failed or exceeded the output bound")
        native = json.loads(result.stdout)
        if native.get("errors") or not isinstance(native.get("paths", {}).get("scanned"), list):
            raise RuntimeError("Native scan errors or missing file coverage")
        scanned = set()
        for name in native["paths"]["scanned"]:
            path = Path(name)
            path = path if path.is_absolute() else copied / path
            scanned.add(path.resolve().relative_to(copied).as_posix())
        if scanned != set(files):
            raise RuntimeError("Native scanner did not cover every declared Python file")
        sarif = json.loads(sarif_path.read_text())
        normalize_locations(sarif, copied)
        for run in sarif["runs"]:
            if not run.get("invocations"):
                run["invocations"] = [{"executionSuccessful": True}]
        return {
            "scope": "configured-python-rules",
            "files": files,
            "scanner_exit": 0,
            "coverage": {
                "expected": sorted(files),
                "native_scanned": sorted(scanned),
                "errors": [],
            },
            "sarif": sarif,
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Static Python scan only; never executes target code"
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("--rules", type=Path, default=Path("/opt/reviewshield/policy/semgrep.yml"))
    args = parser.parse_args()
    print(json.dumps(scan_checkout(args.source, args.rules)))


if __name__ == "__main__":
    main()
