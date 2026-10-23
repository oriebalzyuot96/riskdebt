# Angular library security research

Finds **candidate** problems in published npm packages so a person can review them. A candidate is a lead, not a vulnerability.

## Rules we work by

1. **Only public code, only on this computer.** `scan.mjs` reads the npm registry and unpacks published tarballs locally. It never touches a running website or application. Do not test against live systems without written permission.
2. **A real finding has all four of these:** the value is attacker-controlled; nothing sanitizes it before the dangerous call; the code path is reachable in normal use; and a **local proof of concept** shows the effect. Without a proof of concept, do not report.
3. **Report privately first.** Use the project's `SECURITY.md`, or GitHub's *Security > Report a vulnerability*. Do not open a public issue, post on social media or publish a write-up before a fixed release exists.
4. **Give the maintainer time.** The usual coordinated-disclosure window is 90 days. Ask for a CVE through the GitHub advisory once they agree it is real.
5. **Do not spam.** Maintainers are flooded with unverified automated reports. One confirmed, well-written report is worth more than ten guesses.

## What a good report contains

- Affected package and version range
- One-paragraph summary and impact (who can do what)
- Step-by-step reproduction with a minimal project
- The exact vulnerable lines (permalink to the commit)
- A suggested fix
- Your name as you want it credited

## Workflow

```bash
cd research
node scan.mjs --query "keywords:angular markdown" --limit 12   # search npm and scan the top results
node scan.mjs --packages pdfjs-dist,ngx-markdown             # or scan named packages
```

Options: `--max-size <KB>` (default 8192, so large bundles such as `pdf.worker.mjs` are scanned), `--riskdebt "<command>"` to use another riskdebt build. Test files and constant `innerHTML = '<svg…>'` assignments are filtered out as noise. `work/`, `reports/` and `poc/` are git-ignored: never commit candidate reports for packages that have not been fixed.

Open `reports/candidates-*.md`, start with the highest score, read the surrounding code in the snippet, then in the unpacked package under `work/` follow the data from where it enters to the dangerous call. Most leads will turn out to be safe (the library sanitizes first): that is normal.
