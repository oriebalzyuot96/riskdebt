# Contributing

The easiest and most valuable contribution is a **rule**. Rules are JSON in [`rules/`](rules) and are shared by the Go, Node.js and Python implementations.

## Add a rule

1. **Code smell / framework pattern**: add an entry to `rules/patterns.json` (`pattern`, `exts`, `severity`, `framework`, and a concrete `fix`). Use syntax that works in JavaScript, Python and Go (RE2): no lookaheads or backreferences.
2. **Secret format**: add to `rules/secrets.json`.
3. **EOL date**: add to `rules/eol.json` with a source in the PR.
4. **Compromised release**: add to `rules/compromised.json` with a link to the advisory in the PR.
5. Add a line to a file in `fixtures/vulnerable-app` that triggers it (never a real secret), then run the conformance check.

Every finding must tell the user how to fix it.

## Change behaviour

Behaviour changes go in **all three** implementations in the same PR. `scripts/conformance.mjs` fails if they disagree.

```bash
go test ./...
(cd node && npm test)
PYTHONPATH=python/src python -m unittest discover -s python/tests
node scripts/conformance.mjs
```

## Principles

- Offline, zero runtime dependencies.
- Low false-positive rate beats high coverage; say so in the fix text when a pattern is a heuristic.
- Never print a matched secret.
