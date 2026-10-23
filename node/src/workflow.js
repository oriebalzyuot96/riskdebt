// GitHub Actions hardening (RD009): the checks OpenSSF Scorecard calls Dangerous-Workflow and Token-Permissions,
// plus piping a download into a shell. Must behave exactly like internal/scanner/workflow.go and
// python/src/riskdebt/workflow.py.

const RE_RUN_KEY = /^(run|script)\s*:\s*(.*)$/;
const RE_EXPR = /\$\{\{\s*([^}]*)\}\}/g;
const RE_CURL_PIPE = /\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/i;
const RE_PERM_ANY = /^\s*permissions\s*:/;
const RE_PERM_WRITE_ALL = /^\s*permissions\s*:\s*write-all\s*(?:#.*)?$/;
const RE_HEAD_REF = /\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref|repo\.full_name)|head_ref|event\.workflow_run\.head_(?:sha|branch))\s*\}\}/;
const RE_REF_KEY = /^(?:ref|repository)\s*:/;

// Expression parts an outsider controls (titles, bodies, branch names, commit messages).
const UNTRUSTED_CONTEXTS = [
  'github.event.issue.title', 'github.event.issue.body', 'pull_request.title', 'pull_request.body',
  'head.ref', 'head.label', 'comment.body', 'review.body', 'head_commit.message', 'head_commit.author',
  'github.head_ref', 'workflow_run.head_branch', 'workflow_run.head_commit.message', 'commits.',
  'author.email', 'author.name',
];

const indentOf = (l) => l.length - l.replace(/^[ \t]+/, '').length;

function finding(e, rel, line, severity, check, message, fix, cwe, owasp) {
  e.add('RD009', severity, rel, line, message, fix, { check, cwe, owasp });
}

function checkRunLine(e, rel, line, n) {
  for (const m of line.matchAll(RE_EXPR)) {
    const x = m[1].toLowerCase();
    if (UNTRUSTED_CONTEXTS.some((c) => x.includes(c))) {
      finding(e, rel, n, 'high', 'script-injection',
        `Untrusted input \${{ ${m[1].trim()} }} is interpolated into a script step (script injection)`,
        'Pass the value through an environment variable (env: TITLE: ${{ ... }}) and use "$TITLE" in the script. Never interpolate it into the script text.',
        ['CWE-77'], ['A05:2025']);
      break;
    }
  }
  if (RE_CURL_PIPE.test(line)) {
    finding(e, rel, n, 'high', 'curl-pipe-shell', 'Downloads a script and runs it without verifying it',
      'Download to a file, verify its checksum or signature, then run it. Or install a pinned package instead.',
      ['CWE-494'], ['A08:2025']);
  }
}

export function checkWorkflowRisk(e, rel, text) {
  const lines = text.split('\n');
  let hasPerm = false;
  let trigger = false;
  lines.forEach((raw, i) => {
    const l = raw.replace(/\r+$/, '');
    if (l.trim().startsWith('#')) return;
    if (RE_PERM_ANY.test(l)) hasPerm = true;
    if (RE_PERM_WRITE_ALL.test(l)) {
      finding(e, rel, i + 1, 'high', 'write-all-permissions',
        'The workflow token is granted write access to everything (permissions: write-all)',
        'Replace write-all with only the scopes the job needs, for example permissions: contents: read.',
        ['CWE-250'], ['A02:2025']);
    }
    if (l.includes('pull_request_target')) trigger = true;
  });
  if (!hasPerm) {
    finding(e, rel, 1, 'medium', 'missing-permissions',
      'The workflow has no permissions block, so its token gets the repository default (often read and write)',
      'Add a top-level permissions: contents: read and grant extra scopes per job only where needed.',
      ['CWE-250'], ['A02:2025']);
  }

  let inRun = false;
  let runCol = 0;
  lines.forEach((raw, i) => {
    const l = raw.replace(/\r+$/, '');
    if (inRun) {
      if (l.trim() === '') return;
      if (indentOf(l) > runCol) {
        checkRunLine(e, rel, l, i + 1);
        return;
      }
      inRun = false;
    }
    const t = l.replace(/^[ \t]+/, '');
    if (t.startsWith('#')) return;
    let col = l.length - t.length;
    let rest = t;
    if (rest.startsWith('- ')) {
      const r2 = rest.slice(2).replace(/^ +/, '');
      col += rest.length - r2.length;
      rest = r2;
    }
    if (trigger && RE_REF_KEY.test(rest) && RE_HEAD_REF.test(rest)) {
      finding(e, rel, i + 1, 'critical', 'pwn-request',
        'A pull_request_target workflow checks out code from the pull request, so untrusted code runs with secrets and a write token',
        'Run untrusted pull-request code under the pull_request trigger (no secrets). If you must use pull_request_target, never check out or run the PR head; only label or comment.',
        ['CWE-829'], ['A08:2025', 'A03:2025']);
    }
    const m = rest.match(RE_RUN_KEY);
    if (m) {
      const v = m[2].trim();
      if (v.startsWith('|') || v.startsWith('>')) {
        inRun = true;
        runCol = col;
      } else if (v !== '') checkRunLine(e, rel, v, i + 1);
    }
  });
}
