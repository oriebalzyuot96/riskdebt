package scanner

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

var today = time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)

func TestCleanAppHasNoFindings(t *testing.T) {
	r, err := Scan("../../fixtures/clean-app", Options{Today: today})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("expected none, got %+v", r.Findings)
	}
}

func TestEveryFindingHasAFix(t *testing.T) {
	r, err := Scan("../../fixtures/vulnerable-app", Options{Today: today})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) < 20 {
		t.Fatalf("expected many findings, got %d", len(r.Findings))
	}
	for _, f := range r.Findings {
		if len(f.Fix) < 10 {
			t.Errorf("%s %s:%d has no fix", f.Rule, f.File, f.Line)
		}
	}
}

func TestFrameworkAndSupplyChainDetections(t *testing.T) {
	r, _ := Scan("../../fixtures/vulnerable-app", Options{Today: today})
	want := []string{"[Angular]", "[React]", "[.NET]", "[PHP]", "event-stream"}
	for _, w := range want {
		found := false
		for _, f := range r.Findings {
			if strings.Contains(f.Message, w) {
				found = true
			}
		}
		if !found {
			t.Errorf("no finding mentioning %s", w)
		}
	}
}

func findingKeys(t *testing.T, dir string) []string {
	t.Helper()
	r, err := Scan(dir, Options{Today: today})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, f := range r.Findings {
		keys = append(keys, fmt.Sprintf("%s|%s|%d|%s", f.Rule, f.File, f.Line, f.Message))
	}
	return keys
}

// Hints are a speed optimisation only: the findings must be identical with and without them.
func TestHintsNeverHideAFinding(t *testing.T) {
	for _, dir := range []string{"vulnerable-app", "clean-app", "ignore-app"} {
		path := "../../fixtures/" + dir
		with := findingKeys(t, path)
		disableHints = true
		without := findingKeys(t, path)
		disableHints = false
		if strings.Join(with, "\n") != strings.Join(without, "\n") {
			t.Errorf("%s: findings differ with and without hints\nwith:\n%s\nwithout:\n%s", dir, strings.Join(with, "\n"), strings.Join(without, "\n"))
		}
	}
}

func TestEveryRuleHasHints(t *testing.T) {
	e, err := newEngine(Options{Today: today})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range e.secrets {
		if len(r.Hints) == 0 {
			t.Errorf("secret rule %s has no hints", r.ID)
		}
	}
	for _, r := range e.patterns {
		if len(r.Hints) == 0 {
			t.Errorf("pattern rule %s has no hints", r.ID)
		}
		for _, h := range r.Hints {
			if h != strings.ToLower(h) {
				t.Errorf("pattern rule %s: hint %q must be lower-case", r.ID, h)
			}
		}
	}
}
