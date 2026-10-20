#!/usr/bin/env python3
"""Collect registry dependency license declarations and bundled legal texts."""
import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "THIRD_PARTY_NOTICES.txt")
    args = parser.parse_args()
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--format-version=1"], cwd=ROOT))
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    pending = [package["id"] for package in packages.values() if package["name"] == "sentinel-cli"]
    included = set()
    while pending:
        identity = pending.pop()
        if identity in included:
            continue
        included.add(identity)
        for dependency in nodes[identity]["deps"]:
            if any(kind["kind"] != "dev" for kind in dependency["dep_kinds"]):
                pending.append(dependency["pkg"])
    blocks = ["Sentinel v0.0.1 third-party notices\n\nRegistry packages reachable through non-development CLI dependencies, including target-specific dependencies. Each package retains its upstream licensing terms. License declarations below do not relicense dependencies under Sentinel's MIT license.\n"]
    missing = []
    for package in sorted((packages[key] for key in included if packages[key]["source"]), key=lambda p: (p["name"], p["version"])):
        root = Path(package["manifest_path"]).parent
        texts = []
        for path in sorted(root.rglob("*")):
            if path.is_file() and not path.is_symlink() and path.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE", "PATENTS", "AUTHORS")):
                if path.stat().st_size <= 512 * 1024:
                    texts.append((str(path.relative_to(root)), path.read_text(encoding="utf-8", errors="replace")))
        if not package["license"] or not texts:
            missing.append(package["name"] + " " + package["version"])
        blocks.append("\n" + "=" * 72 + "\n" + package["name"] + " " + package["version"] + "\nDeclared license: " + str(package["license"]) + "\n")
        for name, text in texts:
            blocks.append("\n--- " + name + " ---\n" + text + "\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(blocks), encoding="utf-8")
    if missing:
        raise SystemExit("License text/declaration review required: " + ", ".join(missing))
    print("Third-party notices generated for " + str(sum(bool(packages[key]["source"]) for key in included)) + " registry dependencies")


if __name__ == "__main__":
    main()
