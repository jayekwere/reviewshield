"""Run a local, pinned rule pack without executing target source."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit


def normalize_locations(report: dict[str, Any], root: Path) -> None:
    root = root.resolve()
    for run in report["runs"]:
        for result in run.get("results", []):
            for location in result.get("locations", []):
                artifact = location["physicalLocation"]["artifactLocation"]
                uri = urlsplit(artifact["uri"])
                if (
                    uri.scheme not in {"", "file"}
                    or uri.netloc not in {"", "localhost"}
                    or uri.query
                    or uri.fragment
                ):
                    raise ValueError("Scanner location must identify a checkout file")
                path = Path(unquote(uri.path, errors="strict"))
                resolved = (path if path.is_absolute() else root / path).resolve()
                relative = resolved.relative_to(root)
                if not resolved.is_file():
                    raise ValueError("Scanner location does not identify an existing file")
                artifact["uri"] = relative.as_posix()
                artifact["uriBaseId"] = "%SRCROOT%"


def scan(target: Path, rules: Path, output: Path, semgrep: str = "semgrep") -> None:
    command = [
        semgrep,
        "scan",
        "--config",
        str(rules.resolve()),
        "--sarif",
        "--metrics=off",
        "--disable-version-check",
        "--strict",
        "--no-git-ignore",
        str(target.resolve()),
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"Scanner failed: exit {result.returncode}")
    report = json.loads(result.stdout)
    normalize_locations(report, Path.cwd())
    for run in report["runs"]:
        if not run.get("invocations"):
            run["invocations"] = [{"executionSuccessful": True}]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                "scanner": "Semgrep",
                "report_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                "exit": result.returncode,
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--rules", type=Path, default=Path("policy/semgrep.yml"))
    parser.add_argument("--semgrep", default="semgrep")
    args = parser.parse_args()
    scan(args.target, args.rules, args.output, args.semgrep)
