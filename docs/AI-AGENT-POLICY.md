# AI tool and agent policy (template)

"Govern, don't block." Clear rules about approved tools and data use stop shadow AI without stopping innovation. Copy this file, edit the bracketed parts, and have your security and engineering leads sign off.

## 1. Approved tools

| Tool | Approved for | Data allowed | Owner |
|---|---|---|---|
| [e.g. Claude Code] | [source code in internal repos] | [no customer PII, no production secrets] | [team] |

Anything not listed needs a 5-day review through [channel]. A fast "yes, with conditions" is the goal.

## 2. Treat every agent like a new employee

- **Least privilege.** Allow specific commands (`Bash(npm test)`), never `Bash(*)` or a blanket bypass mode, outside a disposable sandbox.
- **Scoped credentials.** One short-lived, minimum-scope token per agent. Never your personal admin credentials.
- **Secrets by reference.** MCP servers and tools read `${ENV_VAR}`; literal tokens are never committed.
- **Human approval** for anything that deletes data, spends money, sends messages externally, changes permissions or deploys.
- **Logging.** Agent actions are logged somewhere the agent itself cannot edit or disable. Alert if monitoring configuration is changed.

## 3. Supply chain

- Pin dependency versions, commit lockfiles, install with `npm ci` / `--require-hashes`.
- Pin GitHub Actions and MCP servers to exact versions or commit SHAs.
- New dependencies in agent-written code are reviewed like any other.
- A compromised-package report triggers: remove, rotate secrets reachable from affected machines and CI, review lockfile history.

## 4. Foundations

- No end-of-life runtimes in production. Every exception has an owner, a compensating control and a retirement date.

## 5. Enforcement

Run `riskdebt . --fail-on high` in CI and as a pre-commit hook. Review exceptions monthly.
