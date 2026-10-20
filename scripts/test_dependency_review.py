import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("review", Path(__file__).with_name("verify-dependency-review.py"))
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


class ReviewTests(unittest.TestCase):
    def test_review_must_match_lockfile_and_be_recent_and_complete(self):
        now = datetime.datetime(2026, 10, 20, tzinfo=datetime.timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            (root / "Cargo.lock").write_bytes(b"fixture")
            value = {"schema_version": 1, "cargo_lock_sha256": hashlib.sha256(b"fixture").hexdigest(), "reviewed_at": now.isoformat(), "status": "complete", "findings": [], "packages_checked": 1}
            path = root / "docs/dependency-review.json"
            path.write_text(json.dumps(value))
            review.verify(root, now)
            for patch in [{"cargo_lock_sha256": "wrong"}, {"status": "incomplete"}, {"findings": ["unresolved"]}, {"reviewed_at": (now - datetime.timedelta(days=2)).isoformat()}, {"reviewed_at": (now + datetime.timedelta(days=1)).isoformat()}]:
                path.write_text(json.dumps({**value, **patch}))
                with self.assertRaises(ValueError):
                    review.verify(root, now)


if __name__ == "__main__":
    unittest.main()
