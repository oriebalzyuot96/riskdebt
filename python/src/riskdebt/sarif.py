"""SARIF 2.1.0 output (for GitHub code scanning)."""
from __future__ import annotations

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
# The 0-10 score GitHub code scanning uses to show critical/high/medium/low.
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def sarif_rule_id(f: dict) -> str:
    """The SARIF rule id of a finding: the rule family plus its sub-check, e.g. RD008/react-dangerous-html."""
    return f"{f['rule']}/{f['check']}" if f.get("check") else f["rule"]


def _tags(f: dict) -> list:
    return ["security", *[f"external/cwe/{c.lower()}" for c in f["cwe"]], *[f"OWASP-{o}" for o in f["owasp"]]]


def to_sarif(r: dict) -> dict:
    seen: dict[str, dict] = {}
    for f in r["findings"]:
        seen.setdefault(sarif_rule_id(f), f)
    rules = [{"id": i, "name": seen[i]["name"], "shortDescription": {"text": seen[i]["name"]},
              "help": {"text": seen[i]["fix"]},
              "properties": {"tags": _tags(seen[i]), "security-severity": _SECURITY_SEVERITY[seen[i]["severity"]]}}
             for i in sorted(seen)]
    results = [{
        "ruleId": sarif_rule_id(f),
        "level": _LEVEL[f["severity"]],
        "message": {"text": f"{f['message']}\nFix: {f['fix']}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]},
                                            "region": {"startLine": f["line"]}}}],
        "partialFingerprints": {"riskdebt/v1": f["fingerprint"]},
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
