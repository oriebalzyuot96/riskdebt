import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python" / "src"))

from riskdebt.ignore import matches, parse_ignore_line  # noqa: E402


class IgnoreMatcherTest(unittest.TestCase):
    """The same cases drive the Go and Node.js tests, so the three matchers cannot drift apart."""

    def test_shared_cases(self):
        cases = json.loads((ROOT / "fixtures" / "ignore-cases.json").read_text(encoding="utf-8"))
        for c in cases:
            rule = parse_ignore_line(c["pattern"])
            got = rule is not None and matches(rule, c["rel"], c["rel"].rsplit("/", 1)[-1], c["isDir"])
            self.assertEqual(got, c["want"], f"pattern {c['pattern']!r} vs {c['rel']} (dir={c['isDir']})")


if __name__ == "__main__":
    unittest.main()
