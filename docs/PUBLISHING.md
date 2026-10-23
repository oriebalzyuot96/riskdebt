# Publishing (maintainers)

Version lives in five places; bump them together: `internal/scanner/scanner.go` (`Version`), `node/src/scanner.js`, `python/src/riskdebt/scanner.py`, plus `node/package.json` and `python/pyproject.toml`.

## 1. Tag (enables `go install ...@v0.1.1` and the GitHub Action)

```bash
git tag v0.1.1 && git push origin v0.1.1
gh release create v0.1.1 --generate-notes
```

## 2. npm

```bash
cd node
npm login
npm publish --access public   # `prepack` copies ../rules into the package
```

Check first with `npm pack --dry-run`: it must list `rules/*.json`.

## 3. PyPI

```bash
cd python
pip install build twine
python -m build --wheel          # force-includes ../rules into the wheel
twine upload dist/*
```

Check first: `unzip -l dist/*.whl | grep rules`.

Tip: use [trusted publishing](https://docs.npmjs.com/trusted-publishers) / [PyPI trusted publishers](https://docs.pypi.org/trusted-publishers/) from GitHub Actions instead of long-lived tokens.
