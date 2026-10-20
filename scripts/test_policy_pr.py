import importlib.util
from pathlib import Path
import unittest
import os
import subprocess
import tempfile
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('pr_gate', Path(__file__).with_name('check-policy-pr.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
class PolicyPRTests(unittest.TestCase):
    def test_commit_selectors_cannot_be_options_or_shell_expressions(self):
        for value in ['--all', 'HEAD', 'a'*39, 'a'*40+'; command', '$(command)', 'A'*40]:
            with self.assertRaises(ValueError):
                module.commit(value)
        self.assertEqual(module.commit('a'*40), 'a'*40)

    def test_base_policy_rejects_a_pr_that_weakens_its_own_policy(self):
        binary = module.ROOT / 'target' / 'release' / ('sentinel.exe' if os.name == 'nt' else 'sentinel')
        self.assertTrue(binary.is_file(), 'Release binary is required for PR gate acceptance')
        with tempfile.TemporaryDirectory(prefix='sentinel-pr-test-') as folder:
            root = Path(folder).resolve()
            def git(*args):
                return subprocess.check_output(['git', '-c', 'user.name=Sentinel Fixture', '-c', 'user.email=fixture@example.invalid', *args], cwd=root, stderr=subprocess.DEVNULL).decode().strip()
            git('init')
            subprocess.run([str(binary), 'init', '--project', str(root)], check=True, capture_output=True)
            git('add', 'sentinel.yml')
            git('commit', '-m', 'base policy')
            base = git('rev-parse', 'HEAD')
            (root / 'src').mkdir()
            (root / 'src' / 'allowed.py').write_text('# synthetic only\n', encoding='utf-8')
            git('add', 'src/allowed.py')
            git('commit', '-m', 'permitted source change')
            allowed = git('rev-parse', 'HEAD')
            subprocess.run([str(binary), 'init', '--level', 'L0', '--force', '--project', str(root)], check=True, capture_output=True)
            git('add', 'sentinel.yml')
            git('commit', '-m', 'attempt policy weakening')
            denied = git('rev-parse', 'HEAD')
            with patch.object(module, 'ROOT', root):
                self.assertEqual(module.check(binary, base, allowed), 0)
                self.assertEqual(module.check(binary, base, denied), 5)
            self.assertIn('L0', (root / 'sentinel.yml').read_text(encoding='utf-8'))
