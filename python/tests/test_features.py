import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python" / "src"))

from riskdebt import scan  # noqa: E402
from riskdebt.baseline import apply_baseline, new_baseline  # noqa: E402
from riskdebt.sarif import to_sarif  # noqa: E402

TODAY = date(2026, 10, 23)
FIXTURES = ROOT / "fixtures"


class FeaturesTest(unittest.TestCase):
    def test_every_finding_is_tagged(self):
        r = scan(str(FIXTURES / "vulnerable-app"), today=TODAY)
        for f in r["findings"]:
            self.assertTrue(f["cwe"] and f["owasp"], f"{f['rule']} {f['file']}:{f['line']} has no tags")
            self.assertTrue(all(c.startswith("CWE-") for c in f["cwe"]))

    def test_workflow_hardening(self):
        r = scan(str(FIXTURES / "vulnerable-app"), today=TODAY)
        got: dict[str, int] = {}
        for f in r["findings"]:
            if f["rule"] == "RD009":
                got[f["check"]] = got.get(f["check"], 0) + 1
                if f["file"].endswith("risky.yml"):
                    self.assertLess(f["line"], 19, "the safe env: step was flagged")
        self.assertEqual(got, {"missing-permissions": 1, "write-all-permissions": 1, "pwn-request": 1,
                               "script-injection": 2, "curl-pipe-shell": 1})

    def test_fingerprint_survives_line_shifts(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "a.js"
            f.write_text("const a = 1;\neval(userInput);\n")
            before = scan(d, today=TODAY)["findings"][0]
            f.write_text("// new\n// comment\n\nconst a = 1;\neval(userInput);\n")
            shifted = scan(d, today=TODAY)["findings"][0]
            self.assertNotEqual(shifted["line"], before["line"])
            self.assertEqual(shifted["fingerprint"], before["fingerprint"])
            f.write_text("const a = 1;\neval(otherInput);\n")
            self.assertNotEqual(scan(d, today=TODAY)["findings"][0]["fingerprint"], before["fingerprint"])

    def test_identical_findings_get_distinct_fingerprints(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.js").write_text("eval(x);\neval(x);\n")
            f = scan(d, today=TODAY)["findings"]
            self.assertEqual(len(f), 2)
            self.assertNotEqual(f[0]["fingerprint"], f[1]["fingerprint"])

    def test_baseline(self):
        r = scan(str(FIXTURES / "vulnerable-app"), today=TODAY)
        total = len(r["findings"])
        b = new_baseline(r, "0")
        b["findings"].append({"fingerprint": "deadbeefdeadbeefdead", "rule": "RD001", "file": "gone.json", "line": 1})
        again = scan(str(FIXTURES / "vulnerable-app"), today=TODAY)
        apply_baseline(again, b)
        self.assertEqual((len(again["findings"]), again["baselined"], again["baselineStale"]), (0, total, 1))
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.js"
            p.write_text("eval(a);\n")
            base = new_baseline(scan(d, today=TODAY), "0")
            p.write_text("eval(a);\ndocument.write(b);\n")
            nxt = scan(d, today=TODAY)
            apply_baseline(nxt, base)
            self.assertEqual([f["check"] for f in nxt["findings"]], ["js-document-write"])

    def test_sarif_ids_and_tags(self):
        sarif = to_sarif(scan(str(FIXTURES / "vulnerable-app"), today=TODAY))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        ids = [x["id"] for x in rules]
        for want in ("RD008/react-dangerous-html", "RD009/pwn-request", "RD003"):
            self.assertIn(want, ids)
        for r in rules:
            self.assertTrue(any(t.startswith("external/cwe/cwe-") for t in r["properties"]["tags"]), r["id"])
            self.assertTrue(r["properties"]["security-severity"])


if __name__ == "__main__":
    unittest.main()
