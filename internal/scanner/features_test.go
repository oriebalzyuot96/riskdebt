package scanner

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func scanDir(t *testing.T, dir string) *Result {
	t.Helper()
	r, err := Scan(dir, Options{Today: today})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestEveryFindingIsTaggedWithCWEAndOWASP(t *testing.T) {
	r := scanDir(t, "../../fixtures/vulnerable-app")
	for _, f := range r.Findings {
		if len(f.CWE) == 0 || len(f.OWASP) == 0 {
			t.Errorf("%s %s:%d has no CWE/OWASP tags", f.Rule, f.File, f.Line)
		}
		for _, c := range f.CWE {
			if !strings.HasPrefix(c, "CWE-") {
				t.Errorf("%s: bad CWE id %q", f.Rule, c)
			}
		}
	}
	e, err := newEngine(Options{Today: today})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range e.patterns {
		if len(p.CWE) == 0 || len(p.OWASP) == 0 {
			t.Errorf("pattern %s has no CWE/OWASP tags", p.ID)
		}
	}
	for id, m := range e.meta {
		if len(m.CWE) == 0 || len(m.OWASP) == 0 {
			t.Errorf("rule %s has no default CWE/OWASP tags", id)
		}
	}
}

func TestWorkflowRiskChecks(t *testing.T) {
	r := scanDir(t, "../../fixtures/vulnerable-app")
	got := map[string]int{}
	for _, f := range r.Findings {
		if f.Rule == "RD009" {
			got[f.Check]++
			// the "Safe" step (env: + "$TITLE") is on lines 19-22 and must stay clean
			if strings.HasSuffix(f.File, "risky.yml") && f.Line >= 19 {
				t.Errorf("the safe env: step was flagged: %s:%d %s", f.File, f.Line, f.Check)
			}
		}
	}
	want := map[string]int{"missing-permissions": 1, "write-all-permissions": 1, "pwn-request": 1, "script-injection": 2, "curl-pipe-shell": 1}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("RD009 %s: got %d, want %d", k, got[k], n)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected RD009 checks: %v", got)
	}
}

func TestFingerprintSurvivesLineShifts(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.js")
	if err := os.WriteFile(file, []byte("const a = 1;\neval(userInput);\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := scanDir(t, dir)
	if len(before.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(before.Findings))
	}
	if err := os.WriteFile(file, []byte("// new\n// comment\n\nconst a = 1;\neval(userInput);\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after := scanDir(t, dir)
	if after.Findings[0].Line == before.Findings[0].Line {
		t.Fatal("the line number should have moved")
	}
	if after.Findings[0].Fingerprint != before.Findings[0].Fingerprint {
		t.Errorf("fingerprint changed when only the line number moved: %s vs %s", before.Findings[0].Fingerprint, after.Findings[0].Fingerprint)
	}
	// editing the offending line itself makes it a new finding
	if err := os.WriteFile(file, []byte("const a = 1;\neval(otherInput);\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if scanDir(t, dir).Findings[0].Fingerprint == before.Findings[0].Fingerprint {
		t.Error("fingerprint should change when the offending line changes")
	}
}

func TestIdenticalFindingsGetDistinctFingerprints(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.js"), []byte("eval(x);\neval(x);\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := scanDir(t, dir)
	if len(r.Findings) != 2 || r.Findings[0].Fingerprint == r.Findings[1].Fingerprint {
		t.Errorf("two identical lines must have two distinct fingerprints: %+v", r.Findings)
	}
}

func TestBaselineHidesKnownFindingsAndCountsStale(t *testing.T) {
	r := scanDir(t, "../../fixtures/vulnerable-app")
	total := len(r.Findings)
	b := NewBaseline(r)
	if len(b.Findings) != total {
		t.Fatalf("baseline has %d entries, want %d", len(b.Findings), total)
	}
	b.Findings = append(b.Findings, BaselineEntry{Fingerprint: "deadbeefdeadbeefdead", Rule: "RD001", File: "gone.json", Line: 1})
	again := scanDir(t, "../../fixtures/vulnerable-app")
	again.ApplyBaseline(b)
	if len(again.Findings) != 0 || again.Baselined != total || again.BaselineStale != 1 {
		t.Errorf("after baseline: %d findings, %d hidden, %d stale (want 0, %d, 1)", len(again.Findings), again.Baselined, again.BaselineStale, total)
	}
	// a new finding is not hidden
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.js"), []byte("eval(a);\n"), 0o644)
	known := scanDir(t, dir)
	base := NewBaseline(known)
	os.WriteFile(filepath.Join(dir, "a.js"), []byte("eval(a);\ndocument.write(b);\n"), 0o644)
	next := scanDir(t, dir)
	next.ApplyBaseline(base)
	if len(next.Findings) != 1 || next.Findings[0].Check != "js-document-write" {
		t.Errorf("only the new finding should remain, got %+v", next.Findings)
	}
}

func TestSarifRuleIDsIncludeTheCheckAndTags(t *testing.T) {
	r := scanDir(t, "../../fixtures/vulnerable-app")
	s := SARIF(r)
	run := s["runs"].([]any)[0].(map[string]any)
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	ids := []string{}
	for _, x := range rules {
		m := x.(map[string]any)
		ids = append(ids, m["id"].(string))
		props := m["properties"].(map[string]any)
		hasCWE := false
		for _, tag := range props["tags"].([]string) {
			if strings.HasPrefix(tag, "external/cwe/cwe-") {
				hasCWE = true
			}
		}
		if !hasCWE || props["security-severity"] == "" {
			t.Errorf("SARIF rule %v lacks a CWE tag or security-severity", m["id"])
		}
	}
	sort.Strings(ids)
	joined := strings.Join(ids, " ")
	for _, want := range []string{"RD008/react-dangerous-html", "RD009/pwn-request", "RD003"} {
		if !strings.Contains(joined, want) {
			t.Errorf("SARIF rule ids are missing %s: %s", want, joined)
		}
	}
}
