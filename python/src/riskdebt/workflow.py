"""GitHub Actions hardening (RD009): the checks OpenSSF Scorecard calls Dangerous-Workflow and Token-Permissions,
plus piping a download into a shell. Must behave exactly like internal/scanner/workflow.go and node/src/workflow.js."""
from __future__ import annotations

import re

RE_RUN_KEY = re.compile(r"^(run|script)\s*:\s*(.*)$")
RE_EXPR = re.compile(r"\$\{\{\s*([^}]*)\}\}")
RE_CURL_PIPE = re.compile(r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b", re.I)
RE_PERM_ANY = re.compile(r"^\s*permissions\s*:")
RE_PERM_WRITE_ALL = re.compile(r"^\s*permissions\s*:\s*write-all\s*(?:#.*)?$")
RE_HEAD_REF = re.compile(
    r"\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref|repo\.full_name)|head_ref|event\.workflow_run\.head_(?:sha|branch))\s*\}\}")
RE_REF_KEY = re.compile(r"^(?:ref|repository)\s*:")

# Expression parts an outsider controls (titles, bodies, branch names, commit messages).
UNTRUSTED_CONTEXTS = [
    "github.event.issue.title", "github.event.issue.body", "pull_request.title", "pull_request.body",
    "head.ref", "head.label", "comment.body", "review.body", "head_commit.message", "head_commit.author",
    "github.head_ref", "workflow_run.head_branch", "workflow_run.head_commit.message", "commits.",
    "author.email", "author.name",
]


def _indent_of(l: str) -> int:
    return len(l) - len(l.lstrip(" \t"))


def _finding(e, rel, line, severity, check, message, fix, cwe, owasp) -> None:
    e.add("RD009", severity, rel, line, message, fix, {"check": check, "cwe": cwe, "owasp": owasp})


def _check_run_line(e, rel: str, line: str, n: int) -> None:
    for m in RE_EXPR.finditer(line):
        x = m.group(1).lower()
        if any(c in x for c in UNTRUSTED_CONTEXTS):
            _finding(e, rel, n, "high", "script-injection",
                     "Untrusted input ${{ " + m.group(1).strip() + " }} is interpolated into a script step (script injection)",
                     'Pass the value through an environment variable (env: TITLE: ${{ ... }}) and use "$TITLE" in the script. Never interpolate it into the script text.',
                     ["CWE-77"], ["A05:2025"])
            break
    if RE_CURL_PIPE.search(line):
        _finding(e, rel, n, "high", "curl-pipe-shell", "Downloads a script and runs it without verifying it",
                 "Download to a file, verify its checksum or signature, then run it. Or install a pinned package instead.",
                 ["CWE-494"], ["A08:2025"])


def check_workflow_risk(e, rel: str, text: str) -> None:
    lines = text.split("\n")
    has_perm = False
    trigger = False
    for i, raw in enumerate(lines):
        l = raw.rstrip("\r")
        if l.strip().startswith("#"):
            continue
        if RE_PERM_ANY.match(l):
            has_perm = True
        if RE_PERM_WRITE_ALL.match(l):
            _finding(e, rel, i + 1, "high", "write-all-permissions",
                     "The workflow token is granted write access to everything (permissions: write-all)",
                     "Replace write-all with only the scopes the job needs, for example permissions: contents: read.",
                     ["CWE-250"], ["A02:2025"])
        if "pull_request_target" in l:
            trigger = True
    if not has_perm:
        _finding(e, rel, 1, "medium", "missing-permissions",
                 "The workflow has no permissions block, so its token gets the repository default (often read and write)",
                 "Add a top-level permissions: contents: read and grant extra scopes per job only where needed.",
                 ["CWE-250"], ["A02:2025"])

    in_run = False
    run_col = 0
    for i, raw in enumerate(lines):
        l = raw.rstrip("\r")
        if in_run:
            if l.strip() == "":
                continue
            if _indent_of(l) > run_col:
                _check_run_line(e, rel, l, i + 1)
                continue
            in_run = False
        t = l.lstrip(" \t")
        if t.startswith("#"):
            continue
        col = len(l) - len(t)
        rest = t
        if rest.startswith("- "):
            r2 = rest[2:].lstrip(" ")
            col += len(rest) - len(r2)
            rest = r2
        if trigger and RE_REF_KEY.match(rest) and RE_HEAD_REF.search(rest):
            _finding(e, rel, i + 1, "critical", "pwn-request",
                     "A pull_request_target workflow checks out code from the pull request, so untrusted code runs with secrets and a write token",
                     "Run untrusted pull-request code under the pull_request trigger (no secrets). If you must use pull_request_target, never check out or run the PR head; only label or comment.",
                     ["CWE-829"], ["A08:2025", "A03:2025"])
        m = RE_RUN_KEY.match(rest)
        if m:
            v = m.group(2).strip()
            if v.startswith("|") or v.startswith(">"):
                in_run = True
                run_col = col
            elif v != "":
                _check_run_line(e, rel, v, i + 1)
