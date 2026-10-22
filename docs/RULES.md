# Rule reference

Every finding prints a `problem` and a `fix`. Data lives in [`rules/`](../rules).

| ID | Name | Severity | Fix in one line |
|---|---|---|---|
| RD001 | unpinned-dependency | medium / high (`latest`, `*`, git/URL) | Pin exact versions, commit a lockfile, update via reviewed PRs |
| RD002 | missing-lockfile | medium (npm) / low (pip hashes) | Commit the lockfile; `npm ci`; `pip install --require-hashes` |
| RD003 | known-compromised-package | critical | Remove/upgrade, rotate reachable secrets |
| RD004 | hardcoded-secret | critical / high | Revoke and rotate, move to env or secret manager |
| RD005 | end-of-life-runtime | high (EOL) / medium (EOL within 180 days) | Upgrade, or isolate and set a retirement date |
| RD006 | ai-agent-config-risk | high / medium | Least privilege, pin MCP servers, secrets by reference |
| RD007 | unpinned-github-action | medium | Pin to a 40-char commit SHA |
| RD008 | insecure-code-pattern | critical / high / medium | See the pattern's own fix |

## RD008 patterns

| Framework | Pattern | Severity |
|---|---|---|
| React | `dangerouslySetInnerHTML` | high |
| Angular | `bypassSecurityTrust*` | high |
| Angular | dev-server host check disabled | medium |
| JavaScript | `eval` / `new Function` | high |
| JavaScript | `innerHTML =` / `document.write` | medium |
| Node.js | TLS verification disabled | high |
| SPA | auth token in `localStorage` | medium |
| .NET | `SqlCommand` built by concatenation | high |
| .NET | `FromSqlRaw($"...")` | high |
| .NET | `BinaryFormatter` and similar | high |
| .NET | Json.NET `TypeNameHandling` | high |
| .NET | `Html.Raw` | medium |
| .NET | `AllowAnyOrigin()` | medium |
| .NET | certificate validation disabled | high |
| .NET | password in connection string | high |
| PHP | request data to `system`/`exec` | critical |
| PHP | `unserialize($_POST...)` | critical |
| PHP | `eval` | high |
| Python | `verify=False` | high |
| Python | `shell=True` | medium |
| Python | `pickle.load(s)` | medium |

## Scope notes

- EOL checks look at pinned runtime files (`.nvmrc`, `.node-version`, `.python-version`, `.php-version`, `runtime.txt`, `Dockerfile FROM`). `engines` ranges are not flagged because they state a minimum, not the version in use.
- Compromised-package checks compare exact versions from `package.json`, `package-lock.json` and `requirements.txt` against `rules/compromised.json`.
- Patterns are line-based heuristics. Use `riskdebt-ignore` on a line you have reviewed.
