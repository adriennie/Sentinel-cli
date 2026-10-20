"""Offline installer regression tests: disposable destinations and synthetic archives."""
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(os.name == 'nt', 'Bash installer targets macOS and GNU/Linux; Windows uses release ZIPs')
class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sentinel-installer-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.bin = self.root / 'tools'
        self.bin.mkdir()
        self.assets = self.root / 'assets'
        self.assets.mkdir()
        self.destination = self.root / 'install with spaces'
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        FIXTURES=str(self.assets), FIXTURE_OS='Darwin', FIXTURE_ARCH='arm64',
                        FIXTURE_LIBC='glibc 2.39', REQUESTS=str(self.root / 'requests'), TMPDIR=str(self.root))
        self.env.pop('SENTINEL_INSTALL_DIR', None)
        self.tool('uname', '#!/bin/sh\nif [ "$1" = -s ]; then echo "$FIXTURE_OS"; else echo "$FIXTURE_ARCH"; fi\n')
        self.tool('getconf', '#!/bin/sh\nprintf "%s\\n" "$FIXTURE_LIBC"\n')
        self.tool('curl', '#!' + sys.executable + '\n' + '''import os, pathlib, shutil, sys
args=sys.argv[1:]; url=args[-1]
assert url.startswith('https://github.com/adriennie/Sentinel-cli/')
assert args[args.index('--proto')+1]=='=https' and args[args.index('--proto-redir')+1]=='=https'
with open(os.environ['REQUESTS'],'a') as log: log.write(url+'\\n')
if os.environ.get('FAIL_DOWNLOAD'): sys.exit(22)
if url.endswith('/latest'):
 print('https://github.com/adriennie/Sentinel-cli/releases/tag/v0.0.2',end='')
else:
 shutil.copyfile(pathlib.Path(os.environ['FIXTURES']) / url.rsplit('/',1)[-1],args[args.index('--output')+1])
''')
        self.tool('gh', '#!' + sys.executable + '\n' + '''import os,pathlib,shutil,sys
args=sys.argv[1:]
if args[:2]==['release','view']:
 print(os.environ.get('DRAFT','false') if 'isDraft' in args else 'v0.0.2')
elif args[:2]==['release','download']:
 destination=pathlib.Path(args[args.index('--dir')+1])
 for index,arg in enumerate(args):
  if arg=='--pattern': shutil.copyfile(pathlib.Path(os.environ['FIXTURES'])/args[index+1],destination/args[index+1])
else: sys.exit(2)
''')
        self.archive()

    def tool(self, name, body):
        path = self.bin / name
        path.write_text(body, encoding='utf-8')
        path.chmod(0o755)

    def archive(self, target='aarch64-apple-darwin', kind='regular', identity='0.0.2'):
        name = 'sentinel-0.0.2-' + target
        asset = self.assets / (name + '.tar.gz')
        data = ('#!/bin/sh\nprintf "sentinel ' + identity + '\\n"\n').encode()
        with tarfile.open(asset, 'w:gz') as tar:
            member = tarfile.TarInfo(name + '/sentinel')
            member.mode = 0o755
            if kind == 'symlink':
                member.type = tarfile.SYMTYPE
                member.linkname = '/outside/sentinel'
                tar.addfile(member)
            else:
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
                if kind == 'duplicate':
                    tar.addfile(member, io.BytesIO(data))
        self.checksum = hashlib.sha256(asset.read_bytes()).hexdigest() + '  ' + asset.name + '\n'
        (self.assets / 'SHA256SUMS').write_text(self.checksum, encoding='utf-8')

    def run_install(self, *args):
        result = subprocess.run(['bash', str(ROOT / 'install.sh'), '--install-dir', str(self.destination), *args],
                                env=self.env, capture_output=True, text=True)
        self.assertFalse(list(self.root.glob('sentinel-install.*')), 'Temporary downloads were not cleaned up')
        self.assertFalse(list(self.destination.glob('.sentinel-install.*')), 'Staged binary was not cleaned up')
        return result

    def test_latest_installs_verified_binary_and_reports_path_without_editing_profiles(self):
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Installed sentinel 0.0.2', result.stdout)
        self.assertEqual(subprocess.check_output([str(self.destination / 'sentinel'), '--version'], text=True).strip(), 'sentinel 0.0.2')
        self.assertIn('/releases/latest', (self.root / 'requests').read_text())
        self.assertFalse((self.root / '.zshrc').exists())

    def test_explicit_version_and_authenticated_private_download(self):
        result = self.run_install('--version', 'v0.0.2', '--github')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / 'requests').exists())

    def test_existing_binary_preserved_and_force_replaces(self):
        self.destination.mkdir()
        binary = self.destination / 'sentinel'
        binary.write_text('existing user binary')
        self.assertNotEqual(self.run_install('--version', '0.0.2').returncode, 0)
        self.assertEqual(binary.read_text(), 'existing user binary')
        self.assertEqual(self.run_install('--version', '0.0.2', '--force').returncode, 0)

    def test_checksum_failure_preserves_previous_binary(self):
        self.destination.mkdir()
        binary = self.destination / 'sentinel'
        binary.write_text('original')
        (self.assets / 'SHA256SUMS').write_text('0' * 64 + self.checksum[64:])
        result = self.run_install('--version', '0.0.2', '--force')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Checksum verification failed', result.stderr)
        self.assertEqual(binary.read_text(), 'original')

    def test_duplicate_checksums_are_rejected(self):
        (self.assets / 'SHA256SUMS').write_text(self.checksum * 2)
        self.assertNotEqual(self.run_install('--version', '0.0.2').returncode, 0)
        self.assertFalse((self.destination / 'sentinel').exists())

    def test_duplicate_or_symlink_binary_is_rejected(self):
        for kind in ('duplicate', 'symlink'):
            with self.subTest(kind=kind):
                self.archive(kind=kind)
                self.assertNotEqual(self.run_install('--version', '0.0.2').returncode, 0)
                self.assertFalse((self.destination / 'sentinel').exists())

    def test_wrong_binary_version_is_rejected(self):
        self.archive(identity='9.9.9')
        result = self.run_install('--version', '0.0.2')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.destination / 'sentinel').exists())

    def test_destination_symlink_is_never_replaced(self):
        self.destination.mkdir()
        original = self.root / 'original'
        original.write_text('untouched')
        (self.destination / 'sentinel').symlink_to(original)
        self.assertNotEqual(self.run_install('--version', '0.0.2', '--force').returncode, 0)
        self.assertEqual(original.read_text(), 'untouched')

    def test_linux_intel_and_supported_macos_architectures(self):
        for os_name, arch, target in [('Linux', 'x86_64', 'x86_64-unknown-linux-gnu'),
                                      ('Darwin', 'x86_64', 'x86_64-apple-darwin')]:
            with self.subTest(target=target):
                self.env.update(FIXTURE_OS=os_name, FIXTURE_ARCH=arch)
                self.archive(target=target)
                result = self.run_install('--version', '0.0.2', '--force')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(target, result.stderr)

    def test_unsupported_architecture_old_glibc_and_musl_fail_before_download(self):
        for os_name, arch, libc in [('Linux', 'aarch64', 'glibc 2.39'), ('Linux', 'x86_64', 'glibc 2.38'),
                                    ('Linux', 'x86_64', 'musl'), ('MINGW64_NT', 'x86_64', '')]:
            with self.subTest(platform=(os_name, arch, libc)):
                self.env.update(FIXTURE_OS=os_name, FIXTURE_ARCH=arch, FIXTURE_LIBC=libc)
                self.assertNotEqual(self.run_install().returncode, 0)
                self.assertFalse((self.root / 'requests').exists())

    def test_invalid_version_draft_and_network_failure_never_install(self):
        self.assertNotEqual(self.run_install('--version', '../../outside').returncode, 0)
        self.env['DRAFT'] = 'true'
        self.assertNotEqual(self.run_install('--version', '0.0.2', '--github').returncode, 0)
        self.env['FAIL_DOWNLOAD'] = 'true'
        self.assertNotEqual(self.run_install('--version', '0.0.2').returncode, 0)
        self.assertFalse((self.destination / 'sentinel').exists())

    def test_help_needs_no_download(self):
        result = self.run_install('--help')
        self.assertEqual(result.returncode, 0)
        self.assertIn('no sudo', result.stdout)
        self.assertFalse((self.root / 'requests').exists())
