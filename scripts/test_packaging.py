import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("package_release", Path(__file__).with_name("package-release.py"))
package_release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package_release)


class PackagingTests(unittest.TestCase):
    def test_corruption_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            archive = directory / "fixture.zip"
            archive.write_bytes(b"original")
            package_release.checksums(directory)
            archive.write_bytes(b"corrupted")
            with self.assertRaisesRegex(ValueError, "Checksum mismatch"):
                package_release.verify(directory)

    def test_unsafe_checksum_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            (directory / "SHA256SUMS").write_text("0" * 64 + "  ../outside.zip\n")
            with self.assertRaisesRegex(ValueError, "Unsafe"):
                package_release.verify(directory)

    def test_missing_targets_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            (directory / "SHA256SUMS").write_text("")
            with self.assertRaisesRegex(ValueError, "archive count"):
                package_release.verify(directory, expected_count=4)


if __name__ == "__main__":
    unittest.main()
