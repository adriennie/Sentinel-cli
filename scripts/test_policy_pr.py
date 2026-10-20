import importlib.util
from pathlib import Path
import unittest
spec = importlib.util.spec_from_file_location('pr_gate', Path(__file__).with_name('check-policy-pr.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
class PolicyPRTests(unittest.TestCase):
    def test_commit_selectors_cannot_be_options_or_shell_expressions(self):
        for value in ['--all', 'HEAD', 'a'*39, 'a'*40+'; command', '$(command)', 'A'*40]:
            with self.assertRaises(ValueError):
                module.commit(value)
        self.assertEqual(module.commit('a'*40), 'a'*40)
