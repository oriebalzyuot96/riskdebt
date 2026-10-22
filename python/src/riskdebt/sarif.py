"""SARIF 2.1.0 output (for GitHub code scanning)."""
from __future__ import annotations

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_sarif(r: dict) -> dict:
    seen: dict[str, dict] = {}
    for f in r["findings"]:
        seen.setdefault(f["rule"], f)
    rules = [{"id": i, "name": seen[i]["name"], "shortDescription": {"text": seen[i]["name"]},
              "help": {"text": seen[i]["fix"]}} for i in sorted(seen)]
    results = [{
        "ruleId": f["rule"],
        "level": _LEVEL[f["severity"]],
        "message": {"text": f"{f['message']}\nFix: {f['fix']}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]},
                                            "region": {"startLine": f["line"]}}}],
    } for f in r["findings"]]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "riskdebt", "version": r["version"],
                                "informationUri": "https://github.com/oriebalzyuot96/riskdebt", "rules": rules}},
            "results": results,
        }],
    }
