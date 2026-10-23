package scanner

import (
	"encoding/json"
	"os"
	"path"
	"testing"
)

// The same cases drive the Node.js and Python tests, so the three matchers cannot drift apart.
func TestIgnoreMatcherSharedCases(t *testing.T) {
	data, err := os.ReadFile("../../fixtures/ignore-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Pattern string `json:"pattern"`
		Rel     string `json:"rel"`
		IsDir   bool   `json:"isDir"`
		Want    bool   `json:"want"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		rule, ok := parseIgnoreLine(c.Pattern)
		got := ok && rule.matches(c.Rel, path.Base(c.Rel), c.IsDir)
		if got != c.Want {
			t.Errorf("pattern %q vs %q (dir=%v): got %v, want %v", c.Pattern, c.Rel, c.IsDir, got, c.Want)
		}
	}
}
