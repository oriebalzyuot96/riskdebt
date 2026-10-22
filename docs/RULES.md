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
| Any | token / API key in a URL query string | medium |
| SPA | token in `localStorage` **or `sessionStorage`** | medium |
| SPA | token/session cookie written via `document.cookie` (cannot be HttpOnly) | medium |
| JavaScript | token or password written to `console.*` | medium |
| Node.js | JWT `none` algorithm; JWT signed with a hard-coded secret | high |
| Node.js | SQL from template literals / concatenation; CORS `*`; MD5/SHA-1 | high / medium |
| .NET | cookie `HttpOnly`/`Secure` = false | high |
| .NET | JWT `Validate*` flags set to false | high |
| .NET | `[IgnoreAntiforgeryToken]`; `UseDeveloperExceptionPage` | medium |
| PHP | `include($_GET[..])`; request data in SQL | critical |
| Python | `debug=True`; MD5/SHA-1 | medium |
| Docker | `FROM image:latest` | medium |

## Where are tokens stored?

riskdebt answers this directly. It flags tokens kept in web storage, written to cookies from script, sent in URLs, logged to the console, hard-coded in config/MCP files, and signing keys committed in code. The recommended home for a session token is a server-set `HttpOnly; Secure; SameSite` cookie, and for secrets an environment variable or secret manager.

## Scope notes

- EOL checks look at pinned runtime files (`.nvmrc`, `.node-version`, `.python-version`, `.php-version`, `runtime.txt`, `Dockerfile FROM`). `engines` ranges are not flagged because they state a minimum, not the version in use.
- Compromised-package checks compare exact versions from `package.json`, `package-lock.json` and `requirements.txt` against `rules/compromised.json`.
- Patterns are line-based heuristics. Use `riskdebt-ignore` on a line you have reviewed.
