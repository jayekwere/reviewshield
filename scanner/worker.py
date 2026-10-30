"""Credential-free Python static scanning with explicit file coverage evidence."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from scanner.scan import normalize_locations


def scan_manifest(raw: bytes, rules: Path) -> dict[str, Any]:
    if len(raw) > 12_000_000:
        raise ValueError("Input manifest exceeds byte bound")
    value = json.loads(raw)
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "files"}
        or value["schema_version"] != "1.0"
        or not isinstance(value["files"], list)
        or not 1 <= len(value["files"]) <= 500
    ):
        raise ValueError("Invalid input manifest")
    total = 0
    names: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="reviewshield-manifest-") as directory:
        root = Path(directory)
        for item in value["files"]:
            if not isinstance(item, dict) or set(item) != {"path", "content_base64", "sha256"}:
                raise ValueError("Invalid manifest file")
            name = item["path"]
            if (
                not isinstance(name, str)
                or not 1 <= len(name) <= 512
                or any(part in {"", ".", ".."} for part in name.split("/"))
                or any(ord(c) < 32 or ord(c) == 127 or c in "\\:?#%" for c in name)
                or not name.endswith(".py")
                or name in names
                or not isinstance(item["content_base64"], str)
                or not isinstance(item["sha256"], str)
            ):
                raise ValueError("Unsafe or duplicate manifest file")
            try:
                data = base64.b64decode(item["content_base64"], validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ValueError("Invalid manifest base64") from exc
            total += len(data)
            if (
                len(data) > 1_000_000
                or total > 8_388_608
                or hashlib.sha256(data).hexdigest() != item["sha256"]
            ):
                raise ValueError("Manifest source digest or size mismatch")
            names.add(name)
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            destination.touch(mode=0o600, exist_ok=False)
            destination.write_bytes(data)
        return scan_checkout(root, rules)


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
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument("--stdin", action="store_true", help="Read a bounded source manifest")
    parser.add_argument("--rules", type=Path, default=Path("/opt/reviewshield/policy/semgrep.yml"))
    args = parser.parse_args()
    if args.stdin and args.source is None:
        result = scan_manifest(sys.stdin.buffer.read(12_000_001), args.rules)
    elif args.source is not None and not args.stdin:
        result = scan_checkout(args.source, args.rules)
    else:
        parser.error("Specify a source directory or --stdin")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
