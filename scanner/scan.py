"""Run a local, pinned rule pack without executing target source."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def scan(target: Path, rules: Path, output: Path, semgrep: str = "semgrep") -> None:
    command = [semgrep, "scan", "--config", str(rules.resolve()), "--sarif", "--metrics=off", "--disable-version-check", "--strict", "--no-git-ignore", str(target.resolve())]
    result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"Scanner failed: exit {result.returncode}")
    report = json.loads(result.stdout)
    for run in report["runs"]:
        if not run.get("invocations"):
            run["invocations"] = [{"executionSuccessful": True}]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"scanner": "Semgrep", "report_sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "exit": result.returncode}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--rules", type=Path, default=Path("policy/semgrep.yml"))
    parser.add_argument("--semgrep", default="semgrep")
    args = parser.parse_args()
    scan(args.target, args.rules, args.output, args.semgrep)
