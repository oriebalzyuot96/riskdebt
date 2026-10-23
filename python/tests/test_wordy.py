import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python" / "src"))

from riskdebt.scanner import is_wordy, last_quoted  # noqa: E402


class WordyTest(unittest.TestCase):
    """The same cases drive the Go and Node.js tests, so the three implementations cannot drift apart."""

    def test_shared_cases(self):
        cases = json.loads((ROOT / "fixtures" / "wordy-cases.json").read_text(encoding="utf-8"))
        for c in cases:
            self.assertEqual(is_wordy(c["value"]), c["want"], c["value"])

    def test_last_quoted(self):
        self.assertEqual(last_quoted('token: "abc_def_ghi"'), "abc_def_ghi")
        self.assertEqual(last_quoted("\"refreshToken\": 'users/RefreshToken'"), "users/RefreshToken")


if __name__ == "__main__":
    unittest.main()
