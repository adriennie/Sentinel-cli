#!/usr/bin/env python3
"""Evaluate PR writes against the base revision's policy; never execute diff contents."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def commit(value):
    if not re.fullmatch(r'[0-9a-f]{40}', value):
        raise ValueError('A full lowercase commit SHA is required')
    return value

def check(binary, base, head):
    base, head = commit(base), commit(head)
    policy = subprocess.check_output(['git', 'show', base + ':sentinel.yml'], cwd=ROOT)
    if len(policy) > 1024 * 1024:
        raise ValueError('Base policy exceeds limit')
    names = subprocess.check_output(['git', 'diff', '--no-renames', '--name-only', '-z', base, head, '--'], cwd=ROOT)
    paths = [path.decode('utf-8') for path in names.split(b'\0') if path]
    with tempfile.TemporaryDirectory(prefix='sentinel-pr-policy-') as folder:
        config = Path(folder) / 'base-policy.yml'
        changes = Path(folder) / 'changes.json'
        config.write_bytes(policy)
        changes.write_text(json.dumps(paths), encoding='utf-8')
        result = subprocess.run([str(binary.resolve()), 'policy', 'test', '--project', str(ROOT), '--config', str(config), '--changed-files', str(changes), '--format=json'], cwd=ROOT, capture_output=True, text=True)
        if result.returncode:
            print('PR policy gate rejected changes or could not establish permission; approvals are unavailable in this noninteractive gate')
            return result.returncode
        payload = json.loads(result.stdout)
        assert payload['data']['result']['scope'] == 'proposed_project_changes'
        assert payload['data']['result']['passed'] is True
        print('PR policy gate: all proposed writes permitted by the base policy')
        return 0

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--base', default=os.environ.get('SENTINEL_PR_BASE'))
    parser.add_argument('--head', default=os.environ.get('SENTINEL_PR_HEAD'))
    args = parser.parse_args()
    return check(args.binary, args.base or '', args.head or '')

if __name__ == '__main__':
    raise SystemExit(main())
