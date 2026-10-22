package scanner

import (
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
