#!/usr/bin/env python3
"""Run local release checks without live vulnerability APIs; never tag/publish."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(arguments, **kwargs):
    print("+ " + " ".join(str(arg) for arg in arguments), flush=True)
    return subprocess.run(arguments, cwd=ROOT, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--readiness-only", action="store_true", help="Inspect the existing release binary without rebuilding")
    parser.add_argument("--binary", type=Path, help="Use an extracted release binary for readiness-only smoke tests")
    args = parser.parse_args()
    if not args.readiness_only:
        for arguments in [
            ["cargo", "fmt", "--all", "--", "--check"],
            ["cargo", "clippy", "--locked", "--workspace", "--all-targets", "--", "-D", "warnings"],
            ["cargo", "test", "--locked", "--workspace"],
            ["cargo", "build", "--locked", "--workspace", "--release"],
        ]:
            run(arguments)
        run([sys.executable, "-m", "unittest", "discover", "-s", "scripts", "-p", "test_*.py"])
    binary = ROOT / "target" / "release" / ("sentinel.exe" if os.name == "nt" else "sentinel")
    if args.binary is not None:
        if not args.readiness_only:
            parser.error("--binary requires --readiness-only")
        binary = args.binary.resolve()
    if not binary.is_file():
        print("BLOCKED: release binary missing; build it before checking readiness", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory(prefix="sentinel-release-") as directory:
        project = Path(directory) / "project"
        project.mkdir()
        if not args.readiness_only:
            installed = Path(directory) / "installed"
            run(["cargo", "install", "--locked", "--offline", "--path", str(ROOT / "crates/sentinel-cli"), "--root", str(installed)])
            binary = installed / "bin" / binary.name
        run([str(binary), "--version"])
        run([str(binary), "init", "--project", str(project), "--quiet"])
        (project / "Cargo.lock").write_text('version = 4\n[[package]]\nname = "local-fixture"\nversion = "0.1.0"\n', encoding="utf-8")
        run([str(binary), "policy", "check", "--project", str(project), "--quiet"])
        run([str(binary), "scan", "--offline", "--project", str(project), "--quiet"])
        secret = "ghp_" + "A" * 36
        secret_file = project / "synthetic-secret.txt"
        secret_file.write_text(secret, encoding="utf-8")
        secret_result = subprocess.run([str(binary), "scan", "--type", "secrets", "--project", str(project), "--format=json"], capture_output=True, text=True)
        assert secret_result.returncode == 4, "Synthetic secret was not detected"
        assert secret not in secret_result.stdout + secret_result.stderr, "Secret leaked in command output"
        secret_report = json.loads(secret_result.stdout)["data"]
        assert secret_report["complete"] and secret_report["findings"][0]["evidence"]["redacted"] == "[REDACTED]"
        assert secret not in (project / ".sentinel" / "audit.jsonl").read_text(encoding="utf-8"), "Secret leaked in audit log"
        secret_file.unlink()
        result = run([str(binary), "doctor", "--project", str(project), "--format=json"], capture_output=True, text=True)
        report = json.loads(result.stdout)["data"]
        history = run([str(binary), "audit", "--project", str(project), "--format=json"], capture_output=True, text=True)
        assert json.loads(history.stdout)["data"]["complete"], "Audit history is incomplete"
        blockers = []
        for capability in ["dependency_scanning", "secrets_scanning", "audit_logging"]:
            if not report["capabilities"].get(capability):
                blockers.append("Required capability missing: " + capability)
        if report["status"] == "fail":
            blockers.append("Doctor diagnostics failed")
        if blockers:
            print("Implementation checks completed. Release readiness: BLOCKED.")
            for blocker in blockers:
                print("- " + blocker)
            return 1
        print("Local release checks passed. Confirm supported-platform CI and dependency-review results before tagging.")
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (subprocess.CalledProcessError, OSError, AssertionError, KeyError, ValueError) as error:
        print("Release checks failed: " + str(error), file=sys.stderr)
        sys.exit(1)
