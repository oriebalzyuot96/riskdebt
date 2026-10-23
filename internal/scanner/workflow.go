package scanner

import (
	"regexp"
	"strings"
)

// GitHub Actions hardening (RD009): the checks OpenSSF Scorecard calls Dangerous-Workflow and Token-Permissions,
// plus piping a download into a shell. Must behave exactly like node/src/workflow.js and python/src/riskdebt/workflow.py.

var (
	reRunKey       = regexp.MustCompile(`^(run|script)\s*:\s*(.*)$`)
	reExpr         = regexp.MustCompile(`\$\{\{\s*([^}]*)\}\}`)
	reCurlPipe     = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b`)
	rePermAny      = regexp.MustCompile(`^\s*permissions\s*:`)
	rePermWriteAll = regexp.MustCompile(`^\s*permissions\s*:\s*write-all\s*(?:#.*)?$`)
	reHeadRef      = regexp.MustCompile(`\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref|repo\.full_name)|head_ref|event\.workflow_run\.head_(?:sha|branch))\s*\}\}`)
	reRefKey       = regexp.MustCompile(`^(?:ref|repository)\s*:`)
)

// untrustedContexts are expression parts an outsider controls (titles, bodies, branch names, commit messages).
var untrustedContexts = []string{
	"github.event.issue.title", "github.event.issue.body", "pull_request.title", "pull_request.body",
	"head.ref", "head.label", "comment.body", "review.body", "head_commit.message", "head_commit.author",
	"github.head_ref", "workflow_run.head_branch", "workflow_run.head_commit.message", "commits.",
	"author.email", "author.name",
}

func indentOf(l string) int { return len(l) - len(strings.TrimLeft(l, " \t")) }

func (e *engine) workflowFinding(rel string, line int, severity, check, message, fix string, cwe, owasp []string) {
	e.addTagged("RD009", severity, rel, line, message, fix, check, cwe, owasp)
}

func (e *engine) checkRunLine(rel, line string, n int) {
	for _, m := range reExpr.FindAllStringSubmatch(line, -1) {
		x := strings.ToLower(m[1])
		hit := false
		for _, c := range untrustedContexts {
			if strings.Contains(x, c) {
				hit = true
				break
			}
		}
		if hit {
			e.workflowFinding(rel, n, "high", "script-injection",
				"Untrusted input ${{ "+strings.TrimSpace(m[1])+" }} is interpolated into a script step (script injection)",
				"Pass the value through an environment variable (env: TITLE: ${{ ... }}) and use \"$TITLE\" in the script. Never interpolate it into the script text.",
				[]string{"CWE-77"}, []string{"A05:2025"})
			break
		}
	}
	if reCurlPipe.MatchString(line) {
		e.workflowFinding(rel, n, "high", "curl-pipe-shell",
			"Downloads a script and runs it without verifying it",
			"Download to a file, verify its checksum or signature, then run it. Or install a pinned package instead.",
			[]string{"CWE-494"}, []string{"A08:2025"})
	}
}

func (e *engine) checkWorkflowRisk(rel, text string) {
	lines := strings.Split(text, "\n")
	hasPerm, trigger := false, false
	for i, raw := range lines {
		l := strings.TrimRight(raw, "\r")
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		if rePermAny.MatchString(l) {
			hasPerm = true
		}
		if rePermWriteAll.MatchString(l) {
			e.workflowFinding(rel, i+1, "high", "write-all-permissions",
				"The workflow token is granted write access to everything (permissions: write-all)",
				"Replace write-all with only the scopes the job needs, for example permissions: contents: read.",
				[]string{"CWE-250"}, []string{"A02:2025"})
		}
		if strings.Contains(l, "pull_request_target") {
			trigger = true
		}
	}
	if !hasPerm {
		e.workflowFinding(rel, 1, "medium", "missing-permissions",
			"The workflow has no permissions block, so its token gets the repository default (often read and write)",
			"Add a top-level permissions: contents: read and grant extra scopes per job only where needed.",
			[]string{"CWE-250"}, []string{"A02:2025"})
	}

	inRun := false
	runCol := 0
	for i, raw := range lines {
		l := strings.TrimRight(raw, "\r")
		if inRun {
			if strings.TrimSpace(l) == "" {
				continue
			}
			if indentOf(l) > runCol {
				e.checkRunLine(rel, l, i+1)
				continue
			}
			inRun = false
		}
		t := strings.TrimLeft(l, " \t")
		if strings.HasPrefix(t, "#") {
			continue
		}
		col := len(l) - len(t)
		rest := t
		if strings.HasPrefix(rest, "- ") {
			r2 := strings.TrimLeft(rest[2:], " ")
			col += len(rest) - len(r2)
			rest = r2
		}
		if trigger && reRefKey.MatchString(rest) && reHeadRef.MatchString(rest) {
			e.workflowFinding(rel, i+1, "critical", "pwn-request",
				"A pull_request_target workflow checks out code from the pull request, so untrusted code runs with secrets and a write token",
				"Run untrusted pull-request code under the pull_request trigger (no secrets). If you must use pull_request_target, never check out or run the PR head; only label or comment.",
				[]string{"CWE-829"}, []string{"A08:2025", "A03:2025"})
		}
		if m := reRunKey.FindStringSubmatch(rest); m != nil {
			v := strings.TrimSpace(m[2])
			if strings.HasPrefix(v, "|") || strings.HasPrefix(v, ">") {
				inRun = true
				runCol = col
			} else if v != "" {
				e.checkRunLine(rel, v, i+1)
			}
		}
	}
}
