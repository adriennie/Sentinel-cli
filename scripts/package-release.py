#!/usr/bin/env python3
"""Build, checksum, verify and smoke-test bounded Sentinel release archives."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {"x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "x86_64-apple-darwin", "aarch64-apple-darwin"}
VERSION = re.search(r'^version = "([^"]+)"$', (ROOT / "Cargo.toml").read_text(encoding="utf-8"), re.MULTILINE).group(1)


def digest(path):
    with path.open("rb") as file:
        value = hashlib.sha256()
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            value.update(chunk)
        return value.hexdigest()


def checksums(directory):
    archives = sorted([*directory.glob("*.tar.gz"), *directory.glob("*.zip")])
    if not archives:
        raise ValueError("No release archives found")
    (directory / "SHA256SUMS").write_text("".join(digest(path) + "  " + path.name + "\n" for path in archives), encoding="utf-8")


def build(target, binary, output):
    if target not in TARGETS:
        raise ValueError("Unsupported release target")
    output.mkdir(parents=True, exist_ok=True)
    notices = output / "THIRD_PARTY_NOTICES.txt"
    subprocess.run([sys.executable, str(ROOT / "scripts/third-party-notices.py"), "--output", str(notices)], cwd=ROOT, check=True)
    identity = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    binary_name = "sentinel.exe" if "windows" in target else "sentinel"
    toolchain = subprocess.check_output(["rustc", "--version"], cwd=ROOT, text=True).strip()
    metadata = {"schema_version": 1, "version": VERSION, "commit": identity, "target": target, "rustc": toolchain, "cargo_lock_sha256": digest(ROOT / "Cargo.lock"), "binary_sha256": digest(binary)}
    base = "sentinel-" + VERSION + "-" + target
    files = {binary_name: binary.read_bytes(), "LICENSE": (ROOT / "LICENSE").read_bytes(), "THIRD_PARTY_NOTICES.txt": notices.read_bytes(), "README.md": (ROOT / "INSTALL.md").read_bytes(), "CHANGELOG.md": (ROOT / "CHANGELOG.md").read_bytes(), "BUILD.json": (json.dumps(metadata, indent=2) + "\n").encode()}
    archive = output / (base + (".zip" if "windows" in target else ".tar.gz"))
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
            for name, data in sorted(files.items()):
                info = zipfile.ZipInfo(base + "/" + name, date_time=(2026, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (0o755 if name == binary_name else 0o644) << 16
                zipped.writestr(info, data)
    else:
        with archive.open("wb") as output_file, gzip.GzipFile(filename="", fileobj=output_file, mode="wb", mtime=0) as compressed, tarfile.open(fileobj=compressed, mode="w") as tar:
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo(base + "/" + name)
                info.size = len(data)
                info.mode = 0o755 if name == binary_name else 0o644
                tar.addfile(info, io.BytesIO(data))
    checksums(output)
    print(archive)
    return archive


def verify(directory, smoke=False, expected_commit=None, expected_count=None):
    entries = {}
    for line in (directory / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        checksum, name = line.split("  ", 1)
        if Path(name).name != name or name in entries or len(checksum) != 64:
            raise ValueError("Unsafe or duplicate checksum entry")
        entries[name] = checksum
    if not entries or expected_count is not None and len(entries) != expected_count:
        raise ValueError("Unexpected release archive count")
    for name, checksum in entries.items():
        archive = directory / name
        if digest(archive) != checksum:
            raise ValueError("Checksum mismatch: " + name)
        target = next((target for target in TARGETS if name == "sentinel-" + VERSION + "-" + target + (".zip" if "windows" in target else ".tar.gz")), None)
        if target is None:
            raise ValueError("Unexpected archive identity")
        binary_name = "sentinel.exe" if "windows" in target else "sentinel"
        base = "sentinel-" + VERSION + "-" + target
        expected_names = {base + "/" + member for member in [binary_name, "LICENSE", "THIRD_PARTY_NOTICES.txt", "README.md", "CHANGELOG.md", "BUILD.json"]}
        files = {}
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as zipped:
                if len(zipped.infolist()) != len(expected_names) or set(zipped.namelist()) != expected_names:
                    raise ValueError("Unexpected archive members")
                for info in zipped.infolist():
                    if info.file_size > 64 * 1024 * 1024 or ((info.external_attr >> 16) & 0o170000) == 0o120000:
                        raise ValueError("Oversized or symlink archive member")
                    files[info.filename] = zipped.read(info)
        else:
            with tarfile.open(archive, "r:gz") as tar:
                members = tar.getmembers()
                if len(members) != len(expected_names) or {m.name for m in members} != expected_names:
                    raise ValueError("Unexpected archive members")
                for member in members:
                    if not member.isfile() or member.size > 64 * 1024 * 1024:
                        raise ValueError("Unsafe or oversized archive member")
                    files[member.name] = tar.extractfile(member).read()
        metadata = json.loads(files[base + "/BUILD.json"])
        if metadata["target"] != target or metadata["version"] != VERSION or expected_commit and metadata["commit"] != expected_commit:
            raise ValueError("Release metadata does not match expected source/target")
        if metadata["binary_sha256"] != hashlib.sha256(files[base + "/" + binary_name]).hexdigest():
            raise ValueError("Binary does not match build metadata")
        if smoke:
            with tempfile.TemporaryDirectory(prefix="sentinel-archive-") as temporary:
                binary = Path(temporary) / binary_name
                binary.write_bytes(files[base + "/" + binary_name])
                binary.chmod(0o755)
                subprocess.run([sys.executable, str(ROOT / "scripts/check-release.py"), "--readiness-only", "--binary", str(binary)], cwd=ROOT, check=True)
        print("Verified " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    build_parser = modes.add_parser("build")
    build_parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    build_parser.add_argument("--binary", type=Path)
    build_parser.add_argument("--output", type=Path, default=ROOT / "dist")
    sum_parser = modes.add_parser("checksums")
    sum_parser.add_argument("--directory", type=Path, default=ROOT / "dist")
    verify_parser = modes.add_parser("verify")
    verify_parser.add_argument("--directory", type=Path, default=ROOT / "dist")
    verify_parser.add_argument("--smoke", action="store_true")
    verify_parser.add_argument("--expected-commit")
    verify_parser.add_argument("--expected-count", type=int)
    args = parser.parse_args()
    if args.mode == "build":
        binary = args.binary or ROOT / "target/release" / ("sentinel.exe" if "windows" in args.target else "sentinel")
        build(args.target, binary, args.output)
    elif args.mode == "checksums":
        checksums(args.directory)
    else:
        verify(args.directory, args.smoke, args.expected_commit, args.expected_count)


if __name__ == "__main__":
    main()
