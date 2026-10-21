#!/usr/bin/env python3
"""Run local release checks without live vulnerability APIs; never tag/publish."""
import argparse
import hashlib
import time
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


def python_acceptance(binary, directory):
    """Exercise installed and extracted binaries offline on every native runner."""
    project = Path(directory) / "python-project"
    project.mkdir()
    run([str(binary), "init", "--project", str(project), "--quiet"])
    uv = "version=1\n[[package]]\nname='example'\nversion='1.0'\nsource={registry='https://pypi.org/simple'}\n"
    (project / "uv.lock").write_text(uv, encoding="utf-8")
    package = {"ecosystem": "PyPI", "name": "example", "version": "1.0"}
    key = hashlib.sha256(json.dumps(package, separators=(",", ":")).encode()).hexdigest()
    cache = project / ".sentinel" / "cache" / "osv-v1"
    cache.mkdir(parents=True)
    (cache / (key + ".json")).write_text(json.dumps({"schema_version": 1, "package": package, "fetched_at": int(time.time()), "advisories": []}), encoding="utf-8")

    def scan(expected):
        result = subprocess.run([str(binary), "scan", "--type", "dependencies", "--offline", "--project", str(project), "--format=json"], capture_output=True, text=True)
        assert result.returncode == expected, "Python coverage exit code mismatch"
        assert not result.stderr, "Python JSON command wrote diagnostics outside its envelope"
        return json.loads(result.stdout)["data"]

    assert scan(0)["packages_checked"] == 1
    (project / "poetry.lock").write_text("[[package]]\nname='example'\nversion='1.0'\n[metadata]\nlock-version='2.1'\n", encoding="utf-8")
    assert any(d["code"] == "python_lock_conflict" for d in scan(7)["diagnostics"])
    (project / "uv.lock").unlink()
    assert scan(0)["complete"]
    (project / "poetry.lock").unlink()
    (project / "requirements.txt").write_text("-r base.txt\n-c constraints.txt\n", encoding="utf-8")
    (project / "base.txt").write_text("example>=1\n", encoding="utf-8")
    (project / "constraints.txt").write_text("example==1.0\nunused==2\n", encoding="utf-8")
    assert scan(7)["packages_checked"] == 1
    result = run([str(binary), "doctor", "--project", str(project), "--format=json"], capture_output=True, text=True)
    checks = json.loads(result.stdout)["data"]["checks"]
    assert any(c["id"] == "scanner.dependencies" and "transitive coverage" in c["message"] for c in checks)
    marker = "SYNTHETIC_PRIVATE_INDEX_TOKEN"
    (project / "base.txt").write_text("example==1.0\n--index-url https://user:" + marker + "@example.test/simple\n", encoding="utf-8")
    report = scan(7)
    assert report["packages_checked"] == 0
    assert marker not in json.dumps(report), "Private source value leaked"
    assert marker not in (project / ".sentinel" / "audit.jsonl").read_text(encoding="utf-8"), "Private source leaked in audit"
    history = run([str(binary), "audit", "--project", str(project), "--event", "scan.completed", "--format=json"], capture_output=True, text=True)
    assert json.loads(history.stdout)["data"]["complete"]


def v002_acceptance(binary, directory):
    project = Path(directory) / "v002-project"
    project.mkdir()
    run([str(binary), "init", "--project", str(project), "--quiet"])
    (project / "Cargo.lock").write_text('version=4\n[[package]]\nname="local-fixture"\nversion="1.0.0"\n', encoding="utf-8")
    for args in [["policy", "test"], ["redteam"], ["agent", "setup", "claude"], ["agent", "status"], ["approvals", "list"]]:
        result = run([str(binary), *args, "--project", str(project), "--format=json"], capture_output=True, text=True)
        data = json.loads(result.stdout)["data"]
        assert data["schema_version"] == 2
    result = subprocess.run([str(binary), "agent", "hook", "--project", str(project)], input="{}", capture_output=True, text=True)
    assert result.returncode == 0
    assert json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    checkpoint = Path(directory) / "independent-checkpoint.json"
    run([str(binary), "audit", "checkpoint", "--output", str(checkpoint), "--project", str(project), "--quiet"])
    verified = run([str(binary), "audit", "verify", "--checkpoint", str(checkpoint), "--project", str(project), "--format=json"], capture_output=True, text=True)
    assert json.loads(verified.stdout)["data"]["result"]["complete"]
    result = run([str(binary), "scan", "--type", "dependencies", "--offline", "--reachability", "--exploit-aware", "--project", str(project), "--format=json"], capture_output=True, text=True)
    assert json.loads(result.stdout)["data"]["command"] == "scan.enriched"
    secret = "ghp_" + "B" * 36
    (project / "synthetic.txt").write_text(secret, encoding="utf-8")
    result = subprocess.run([str(binary), "scan", "--type", "secrets", "--project", str(project), "--format=sarif"], capture_output=True, text=True)
    assert result.returncode == 4 and secret not in result.stdout + result.stderr
    assert json.loads(result.stdout)["version"] == "2.1.0"

    for provider in ["codex", "copilot"]:
        res = run([str(binary), "agent", "setup", provider, "--project", str(project), "--format=json"], capture_output=True, text=True)
        assert json.loads(res.stdout)["data"]["result"]["healthy"] is True
        res = run([str(binary), "agent", "status", "--provider", provider, "--project", str(project), "--format=json"], capture_output=True, text=True)
        assert json.loads(res.stdout)["data"]["result"]["healthy"] is True


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
        python_acceptance(binary, directory)
        v002_acceptance(binary, directory)
        print("Local release checks passed. Confirm supported-platform CI and dependency-review results before tagging.")
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (subprocess.CalledProcessError, OSError, AssertionError, KeyError, ValueError) as error:
        print("Release checks failed: " + str(error), file=sys.stderr)
        sys.exit(1)
