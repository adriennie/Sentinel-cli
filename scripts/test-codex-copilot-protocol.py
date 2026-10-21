#!/usr/bin/env python3
"""Synthetic protocol runner for Codex and Copilot hook gates; no live API calls required."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid


def test_codex_protocol(sentinel: Path, project: Path):
    print("Testing Codex protocol...", flush=True)
    # Set up codex
    res = subprocess.run(
        [str(sentinel), "agent", "setup", "codex", "--project", str(project), "--format=json"],
        capture_output=True,
        text=True,
        check=True,
    )
    status_data = json.loads(res.stdout)["data"]["result"]
    assert status_data["healthy"] is True, "Codex setup failed health check"
    assert status_data["provider"] == "codex"

    # Start a mock session by writing session.json or using guard env
    nonce = str(uuid.uuid4())
    session_file = project / ".sentinel" / "agent" / "session.json"
    session_data = {
        "nonce": nonce,
        "created": int(os.path.getmtime(str(project / "sentinel.yml"))),
        "scope": ["src/**"],
        "actor": "codex",
    }
    # Sentinel enforces session created within 8h and <= now
    import time
    session_data["created"] = int(time.time())
    session_file.write_text(json.dumps(session_data), encoding="utf-8")

    env = dict(
        os.environ,
        SENTINEL_GUARD_PROVIDER="codex",
        SENTINEL_GUARD_NONCE=nonce,
        SENTINEL_GUARD_PROJECT=str(project),
    )

    # 1. Allowed patch
    allowed_patch = (
        "*** Begin Patch\n"
        "*** Update File: src/main.rs\n"
        "+// Added by synthetic test\n"
        "*** End Patch\n"
    )
    allowed_input = {
        "hook_event_name": "PreToolUse",
        "session_id": "test-session",
        "tool_use_id": "call-codex-1",
        "cwd": str(project),
        "tool_name": "apply_patch",
        "tool_input": {"command": allowed_patch},
    }
    proc = subprocess.run(
        [str(sentinel), "agent", "hook", "--provider", "codex", "--project", str(project)],
        input=json.dumps(allowed_input),
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    resp = json.loads(proc.stdout)
    assert resp["hookSpecificOutput"]["permissionDecision"] == "allow", f"Expected allow, got {resp}"

    # 2. Protected patch (sentinel.yml) -> deny
    denied_patch = (
        "*** Begin Patch\n"
        "*** Update File: sentinel.yml\n"
        "+evil: true\n"
        "*** End Patch\n"
    )
    denied_input = {
        "hook_event_name": "PreToolUse",
        "session_id": "test-session",
        "tool_use_id": "call-codex-2",
        "cwd": str(project),
        "tool_name": "apply_patch",
        "tool_input": {"command": denied_patch},
    }
    proc = subprocess.run(
        [str(sentinel), "agent", "hook", "--provider", "codex", "--project", str(project)],
        input=json.dumps(denied_input),
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    resp = json.loads(proc.stdout)
    assert resp["hookSpecificOutput"]["permissionDecision"] == "deny", f"Expected deny, got {resp}"
    print("Codex protocol passed: allowed edit & protected edit denied.", flush=True)


def test_copilot_protocol(sentinel: Path, project: Path):
    print("Testing Copilot protocol...", flush=True)
    # Set up copilot
    res = subprocess.run(
        [str(sentinel), "agent", "setup", "copilot", "--project", str(project), "--format=json"],
        capture_output=True,
        text=True,
        check=True,
    )
    status_data = json.loads(res.stdout)["data"]["result"]
    assert status_data["healthy"] is True, "Copilot setup failed health check"
    assert status_data["provider"] == "copilot"

    # Start mock session for copilot
    import time
    nonce = str(uuid.uuid4())
    session_file = project / ".sentinel" / "agent" / "session.json"
    session_data = {
        "nonce": nonce,
        "created": int(time.time()),
        "scope": ["src/**"],
        "actor": "copilot",
    }
    session_file.write_text(json.dumps(session_data), encoding="utf-8")

    env = dict(
        os.environ,
        SENTINEL_GUARD_PROVIDER="copilot",
        SENTINEL_GUARD_NONCE=nonce,
        SENTINEL_GUARD_PROJECT=str(project),
    )

    # 1. Allowed create
    allowed_input = {
        "sessionId": "test-copilot-session",
        "cwd": str(project),
        "toolName": "create",
        "toolArgs": {"path": "src/copilot_test.rs", "content": "// copilot test\n"},
    }
    proc = subprocess.run(
        [str(sentinel), "agent", "hook", "--provider", "copilot", "--project", str(project)],
        input=json.dumps(allowed_input),
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    resp = json.loads(proc.stdout)
    assert resp["permissionDecision"] == "allow", f"Expected allow, got {resp}"

    # 2. Protected edit (.github/hooks/sentinel.json) -> deny
    denied_input = {
        "sessionId": "test-copilot-session",
        "cwd": str(project),
        "toolName": "edit",
        "toolArgs": {"path": ".github/hooks/sentinel.json", "content": "{}"},
    }
    proc = subprocess.run(
        [str(sentinel), "agent", "hook", "--provider", "copilot", "--project", str(project)],
        input=json.dumps(denied_input),
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    resp = json.loads(proc.stdout)
    assert resp["permissionDecision"] == "deny", f"Expected deny, got {resp}"

    # 3. Shell execution -> deny
    bash_input = {
        "sessionId": "test-copilot-session",
        "cwd": str(project),
        "toolName": "bash",
        "toolArgs": {"command": "echo malicious"},
    }
    proc = subprocess.run(
        [str(sentinel), "agent", "hook", "--provider", "copilot", "--project", str(project)],
        input=json.dumps(bash_input),
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    resp = json.loads(proc.stdout)
    assert resp["permissionDecision"] == "deny", f"Expected deny, got {resp}"
    print("Copilot protocol passed: allowed create, protected edit denied, shell denied.", flush=True)


def verify_journal_records(project: Path):
    journal_path = project / ".sentinel" / "agent" / "decisions.jsonl"
    assert journal_path.exists(), "Decisions journal does not exist"
    lines = [json.loads(line) for line in journal_path.read_text(encoding="utf-8").splitlines()]
    actors = {item["actor"] for item in lines}
    assert "codex" in actors, f"Expected codex actor in journal, found {actors}"
    assert "copilot" in actors, f"Expected copilot actor in journal, found {actors}"
    print(f"Decisions journal verified: {len(lines)} entries across actors {actors}.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sentinel", required=True, type=Path)
    args = parser.parse_args()
    sentinel = args.sentinel.resolve()

    with tempfile.TemporaryDirectory(prefix="sentinel-codex-copilot-") as tmp:
        project = Path(tmp) / "project"
        project.mkdir()
        src = project / "src"
        src.mkdir()
        (src / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

        # Initialize project
        subprocess.run([str(sentinel), "init", "--project", str(project)], check=True, capture_output=True)

        test_codex_protocol(sentinel, project)
        test_copilot_protocol(sentinel, project)
        verify_journal_records(project)
        print("ALL Codex and Copilot synthetic protocol tests PASSED successfully!")


if __name__ == "__main__":
    main()
