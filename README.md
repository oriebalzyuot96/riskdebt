# riskdebt

[![npm](https://img.shields.io/npm/v/riskdebt?logo=npm)](https://www.npmjs.com/package/riskdebt)
[![PyPI](https://img.shields.io/pypi/v/riskdebt?logo=pypi&logoColor=white)](https://pypi.org/project/riskdebt/)
[![Go Reference](https://pkg.go.dev/badge/github.com/oriebalzyuot96/riskdebt.svg)](https://pkg.go.dev/github.com/oriebalzyuot96/riskdebt)
[![CI](https://github.com/oriebalzyuot96/riskdebt/actions/workflows/ci.yml/badge.svg)](https://github.com/oriebalzyuot96/riskdebt/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Velocity without alignment creates risk debt.** `riskdebt` finds it in seconds, tells you *where* it is, and tells you *how to fix it*.

One zero-dependency scanner, shipped in **three languages** (Go, Node.js, Python) that share the same rules and are tested against each other, so each team can use the stack it already has.

```text
$ riskdebt .

CRITICAL RD003  package.json:6
  problem: event-stream@3.3.6 is a known-compromised release: malicious flatmap-stream dependency ...
  fix:     Remove or upgrade immediately, rotate every secret reachable from machines or CI that installed it ...

HIGH     RD008  user.component.ts:6
  problem: [Angular] bypassSecurityTrust* disables Angular's sanitizer (XSS)
  fix:     Remove the bypass and bind with [innerHTML] so Angular sanitizes it. If unavoidable, sanitize ...

HIGH     RD006  .claude/settings.json:4
  problem: Agent permission mode is bypassPermissions, so every action runs without human approval
  fix:     Use the default or acceptEdits mode and reserve bypass for disposable sandboxes without credentials.

52 findings: 7 critical, 20 high, 24 medium, 1 low
```

## Why this exists

This week's headlines repeat the same story: a popular AI library was compromised for a couple of hours and stole cloud keys, PHP shipped emergency fixes for remote-code-execution bugs while hundreds of thousands of servers run versions that will never be patched, and AI agents are being handed broad permissions with nobody watching. The foundations are not keeping up with the speed of adoption.

`riskdebt` turns four principles into checks you can run in a terminal, a pre-commit hook or CI:

| Principle | What riskdebt checks |
|---|---|
| **Build security in from day one** (treat every AI agent like a new employee: least privilege, scoped credentials, human approval) | Agent configs: unrestricted `Bash(*)`, `bypassPermissions`, unpinned MCP servers, literal tokens in MCP config |
| **Secure the supply chain and foundations** (pin, verify, monitor, retire EOL) | Unpinned/floating dependencies, missing lockfiles, known-compromised releases, unpinned GitHub Actions, end-of-life Node/Python/PHP |
| **Govern, don't block** | A ready-to-adopt [AI tool policy template](docs/AI-AGENT-POLICY.md) plus `--fail-on` so you choose the gate |
| **Fight AI with AI** | Fast, offline, machine-readable (`--format json`) so it slots into automated pipelines and agent loops |

## What it checks

| Rule | Finds | Ecosystems |
|---|---|---|
| RD001 | Unpinned / floating dependencies | npm, pip, NuGet |
| RD002 | Missing lockfile / hashes | npm, pip |
| RD003 | Known-compromised package versions (extendable) | npm, PyPI |
| RD004 | Leaked secrets: AWS, GitHub, Anthropic, OpenAI, Slack, Google, private keys, generic credentials | any text file |
| RD005 | End-of-life runtimes (`.nvmrc`, `.python-version`, `runtime.txt`, `Dockerfile FROM`) | Node, Python, PHP |
| RD006 | Risky AI-agent / MCP configuration | Claude Code, Cursor, VS Code MCP |
| RD007 | GitHub Actions not pinned to a commit SHA | GitHub Actions |
| RD008 | Insecure code patterns, with framework-specific fixes | **Angular, React, .NET, Node.js, PHP, Python** |

### Framework coverage (RD008)

- **Angular**: `bypassSecurityTrust*` (sanitizer bypass), dev-server host check disabled
- **React / SPA**: `dangerouslySetInnerHTML`, auth tokens in `localStorage`, `innerHTML`, `eval`, `document.write`
- **.NET**: SQL built by concatenation / `FromSqlRaw` interpolation, `BinaryFormatter`, Json.NET `TypeNameHandling`, `Html.Raw`, `AllowAnyOrigin`, certificate validation disabled, passwords in connection strings, floating NuGet versions
- **PHP**: user input into `system()`/`exec()`, `unserialize()` on request data, `eval`, EOL PHP versions
- **Node.js / Python**: TLS verification disabled, `shell=True`, `pickle`, SQL injection, CORS `*`, weak hashes, `debug=True`
- **Where tokens are saved**: `localStorage`/`sessionStorage`, `document.cookie`, tokens in URLs, tokens in logs, hard-coded JWT secrets, JWT `none` algorithm, .NET cookies without `HttpOnly`/`Secure`, disabled JWT validation
- **Docker**: mutable `:latest` base images

Every finding includes a `problem` and a concrete `fix`. Full list: [docs/RULES.md](docs/RULES.md).

## Install and run

Pick the implementation that matches your stack. They produce identical findings.

```bash
# Node.js (>= 20) - no install needed
npx riskdebt .

# Python (>= 3.9)
pip install riskdebt
riskdebt .

# Go
go install github.com/oriebalzyuot96/riskdebt/cmd/riskdebt@latest
riskdebt .
```

```text
riskdebt [path] [options]

  -f, --format <text|json|sarif>   output format (default text)
      --fail-on <severity>   exit 1 at or above critical|high|medium|low|none (default high)
      --today <YYYY-MM-DD>   reproducible EOL checks
      --blocklist <file>     add your own compromised-package list
```

Add `// riskdebt-ignore` (any comment style) on a line to suppress a secret or code-pattern finding there.

### In GitHub Actions (with code-scanning alerts)

```yaml
permissions:
  contents: read
  security-events: write   # lets results appear in the Security tab

steps:
  - uses: actions/checkout@v4
  - uses: oriebalzyuot96/riskdebt@main   # pin to a release tag or commit SHA
    with:
      fail-on: high
```

Findings show up as alerts in **Security → Code scanning**, each with its fix. Or output SARIF yourself: `riskdebt . --format sarif > riskdebt.sarif`.

## Make it yours

The point of an internal tool is that it can encode *your* business logic. Everything is data in [`rules/`](rules): add a secret pattern, a framework smell, an EOL date, or a compromised version to a JSON file and all three implementations pick it up. When a new package is compromised, add it to `compromised.json` (or pass `--blocklist`) and your whole org is protected the same day.

## How the three ports stay honest

`scripts/conformance.mjs` runs the Go, Node.js and Python CLIs against shared fixtures and fails CI if their findings differ by even one line number.

```bash
node scripts/conformance.mjs
```

## Honest limits

`riskdebt` is a fast, offline, heuristic first line of defence. It reads files with regexes and a few parsers; it does not do data-flow analysis, query live vulnerability databases, or replace a SAST/SCA product, a pentest, or patching. The EOL and compromised lists are curated by hand: verify against [endoflife.date](https://endoflife.date) and your advisory feed. Expect some false positives; tune with `--fail-on`, `riskdebt-ignore` and your own rules.

## Roadmap

- Live advisory lookups (OSV) behind an opt-in flag
- More lockfile formats (`yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `packages.lock.json`)
- Rules for Java/Spring, Ruby/Rails, Go, Terraform and Kubernetes manifests
- Pre-commit hook

Ideas and rules welcome: see [CONTRIBUTING.md](CONTRIBUTING.md).

## بالعربي

`riskdebt` أداة مفتوحة المصدر تفحص مشروعك وتخبرك **أين المشكلة الأمنية وكيف تصلحها**: حزم غير مثبّتة، أسرار مسرّبة، إصدارات منتهية الدعم (Node / Python / PHP)، إعدادات خطيرة لوكلاء الذكاء الاصطناعي، وثغرات شائعة في Angular وReact و .NET. متوفرة بثلاث لغات (Go وNode.js وPython) بنفس القواعد. القواعد كلها ملفات JSON في مجلد `rules/` فيمكنك إضافة قواعد فريقك بسهولة.

## License

[MIT](LICENSE)
