package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Fingerprints, baselines and --since filtering. Must behave exactly like the Node.js and Python ports, so a
// baseline file written by one implementation works with the others.

func normalizeWS(s string) string { return strings.Join(strings.Fields(s), " ") }

// fingerprintAll gives each finding an id built from the rule, the file and the text of the offending line (not its
// number), so a finding keeps its id when lines above it are added or removed. Findings that share all three get an
// occurrence index. e.findings must already be sorted.
func (e *engine) fingerprintAll(root string) {
	byFile := map[string][]int{}
	for i := range e.findings {
		byFile[e.findings[i].File] = append(byFile[e.findings[i].File], i)
	}
	for file, idxs := range byFile {
		var lines []string
		if data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file))); err == nil {
			lines = strings.Split(string(data), "\n")
		}
		seen := map[string]int{}
		for _, i := range idxs {
			f := &e.findings[i]
			lt := ""
			if f.Line >= 1 && f.Line <= len(lines) {
				lt = normalizeWS(lines[f.Line-1])
			}
			base := f.Rule + "\x00" + file + "\x00" + lt
			n := seen[base]
			seen[base] = n + 1
			sum := sha256.Sum256([]byte(base + "\x00" + strconv.Itoa(n)))
			f.Fingerprint = hex.EncodeToString(sum[:])[:20]
		}
	}
}

// DefaultBaselineFile is read automatically from the scan root when it exists.
const DefaultBaselineFile = ".riskdebt-baseline.json"

type BaselineEntry struct {
	Fingerprint string `json:"fingerprint"`
	Rule        string `json:"rule"`
	File        string `json:"file"`
	Line        int    `json:"line"`
}

type Baseline struct {
	Version     int             `json:"version"`
	Tool        string          `json:"tool"`
	ToolVersion string          `json:"toolVersion"`
	Findings    []BaselineEntry `json:"findings"`
}

// NewBaseline records every finding of a scan as known.
func NewBaseline(r *Result) *Baseline {
	b := &Baseline{Version: 1, Tool: "riskdebt", ToolVersion: Version, Findings: []BaselineEntry{}}
	for _, f := range r.Findings {
		b.Findings = append(b.Findings, BaselineEntry{Fingerprint: f.Fingerprint, Rule: f.Rule, File: f.File, Line: f.Line})
	}
	sort.SliceStable(b.Findings, func(i, j int) bool {
		x, y := b.Findings[i], b.Findings[j]
		if x.File != y.File {
			return x.File < y.File
		}
		if x.Line != y.Line {
			return x.Line < y.Line
		}
		if x.Rule != y.Rule {
			return x.Rule < y.Rule
		}
		return x.Fingerprint < y.Fingerprint
	})
	return b
}

func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("bad baseline %s: %v", path, err)
	}
	if b.Version != 1 {
		return nil, fmt.Errorf("baseline %s has unsupported version %d", path, b.Version)
	}
	return &b, nil
}

func summarize(findings []Finding) map[string]int {
	s := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range findings {
		s[f.Severity]++
	}
	return s
}

// ApplyBaseline hides the findings that are in the baseline and counts baseline entries that match nothing now.
func (r *Result) ApplyBaseline(b *Baseline) {
	known := map[string]bool{}
	for _, e := range b.Findings {
		known[e.Fingerprint] = true
	}
	current := map[string]bool{}
	kept := []Finding{}
	for _, f := range r.Findings {
		current[f.Fingerprint] = true
		if known[f.Fingerprint] {
			r.Baselined++
		} else {
			kept = append(kept, f)
		}
	}
	for _, e := range b.Findings {
		if !current[e.Fingerprint] {
			r.BaselineStale++
		}
	}
	r.Findings = kept
	r.Summary = summarize(kept)
}

type lineRanges struct {
	all    bool
	ranges [][2]int
}

func (l *lineRanges) has(line int) bool {
	if l.all {
		return true
	}
	for _, r := range l.ranges {
		if line >= r[0] && line <= r[1] {
			return true
		}
	}
	return false
}

func runGit(root string, args ...string) (string, error) {
	full := append([]string{"-C", root, "-c", "core.quotepath=false"}, args...)
	cmd := exec.Command("git", full...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s failed: %s", args[0], strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// changedLines returns, per file (relative to root), the lines added or changed since ref in the working tree.
// Untracked files count as changed in full.
func changedLines(root, ref string) (map[string]*lineRanges, error) {
	if strings.HasPrefix(ref, "-") {
		return nil, fmt.Errorf("--since needs a git ref, got %q", ref)
	}
	diff, err := runGit(root, "diff", "--relative", "-U0", "--no-color", "--no-ext-diff", "--no-renames", ref, "--")
	if err != nil {
		return nil, err
	}
	changed := map[string]*lineRanges{}
	cur := ""
	for _, l := range strings.Split(diff, "\n") {
		l = strings.TrimRight(l, "\r")
		switch {
		case strings.HasPrefix(l, "+++ "):
			p := l[4:]
			if i := strings.IndexByte(p, '\t'); i >= 0 {
				p = p[:i]
			}
			if p == "/dev/null" {
				cur = ""
			} else {
				cur = strings.TrimPrefix(p, "b/")
				if changed[cur] == nil {
					changed[cur] = &lineRanges{}
				}
			}
		case strings.HasPrefix(l, "@@") && cur != "":
			i := strings.Index(l, " +")
			if i < 0 {
				continue
			}
			rest := l[i+2:]
			if j := strings.IndexByte(rest, ' '); j >= 0 {
				rest = rest[:j]
			}
			parts := strings.SplitN(rest, ",", 2)
			start, _ := strconv.Atoi(parts[0])
			count := 1
			if len(parts) == 2 {
				count, _ = strconv.Atoi(parts[1])
			}
			if count > 0 {
				changed[cur].ranges = append(changed[cur].ranges, [2]int{start, start + count - 1})
			}
		}
	}
	untracked, err := runGit(root, "ls-files", "--others", "--exclude-standard")
	if err != nil {
		return nil, err
	}
	for _, p := range strings.Split(untracked, "\n") {
		p = strings.TrimRight(p, "\r")
		if p != "" {
			changed[p] = &lineRanges{all: true}
		}
	}
	return changed, nil
}

// FilterSince keeps only findings on lines that changed since the git ref (plus file-level findings, reported on
// line 1, of files that changed at all). This is what a pull request adds.
func (r *Result) FilterSince(root, ref string) error {
	changed, err := changedLines(root, ref)
	if err != nil {
		return err
	}
	kept := []Finding{}
	for _, f := range r.Findings {
		c := changed[f.File]
		if c != nil && (f.Line == 1 || c.has(f.Line)) {
			kept = append(kept, f)
		}
	}
	r.Findings = kept
	r.Summary = summarize(kept)
	r.Since = ref
	return nil
}
