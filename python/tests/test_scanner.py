import sys
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python" / "src"))

from riskdebt import scan  # noqa: E402

TODAY = date(2026, 10, 23)
FIXTURES = ROOT / "fixtures"


class ScannerTest(unittest.TestCase):
    def test_clean_app_has_no_findings(self):
        self.assertEqual(scan(str(FIXTURES / "clean-app"), today=TODAY)["findings"], [])

    def test_every_finding_has_a_fix(self):
        r = scan(str(FIXTURES / "vulnerable-app"), today=TODAY)
        self.assertGreater(len(r["findings"]), 20)
        for f in r["findings"]:
            self.assertGreater(len(f["fix"]), 10, f)

    def test_detects_compromised_package_and_angular_bypass(self):
        r = scan(str(FIXTURES / "vulnerable-app"), today=TODAY)
        self.assertTrue(any(f["rule"] == "RD003" and "event-stream" in f["message"] for f in r["findings"]))
        self.assertTrue(any(f["rule"] == "RD008" and "[Angular]" in f["message"] for f in r["findings"]))


if __name__ == "__main__":
    unittest.main()
