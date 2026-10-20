#!/usr/bin/env python3
"""Require a recent complete, finding-free review of this exact Cargo.lock."""
import datetime
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify(root=ROOT, now=None):
    review = json.loads((root / "docs/dependency-review.json").read_text(encoding="utf-8"))
    lock_hash = hashlib.sha256((root / "Cargo.lock").read_bytes()).hexdigest()
    if review.get("schema_version") != 1 or review.get("cargo_lock_sha256") != lock_hash:
        raise ValueError("Dependency review does not cover this Cargo.lock")
    checked = datetime.datetime.fromisoformat(review["reviewed_at"].replace("Z", "+00:00"))
    now = now or datetime.datetime.now(datetime.timezone.utc)
    age = (now - checked).total_seconds()
    if not 0 <= age <= 86400 or review.get("status") != "complete" or review.get("findings") != []:
        raise ValueError("Dependency review is stale, incomplete, or has unresolved findings")
    if review.get("packages_checked", 0) <= 0:
        raise ValueError("Dependency review contains no checked packages")
    print("Dependency review is current and matches Cargo.lock")


if __name__ == "__main__":
    verify()
