package scanner

import (
	"sort"
	"strings"
)

var sarifLevel = map[string]string{"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}

// securitySeverity is the 0-10 score GitHub code scanning uses to show critical/high/medium/low.
var securitySeverity = map[string]string{"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}

// SarifRuleID is the SARIF rule id of a finding: the rule family plus its sub-check, e.g. RD008/react-dangerous-html.
func SarifRuleID(f Finding) string {
	if f.Check != "" {
		return f.Rule + "/" + f.Check
	}
	return f.Rule
}

func sarifTags(f Finding) []string {
	tags := []string{"security"}
	for _, c := range f.CWE {
		tags = append(tags, "external/cwe/"+strings.ToLower(c))
	}
	for _, o := range f.OWASP {
		tags = append(tags, "OWASP-"+o)
	}
	return tags
}

// SARIF converts a result to a SARIF 2.1.0 log (for GitHub code scanning).
func SARIF(r *Result) map[string]any {
	seen := map[string]Finding{}
	for _, f := range r.Findings {
		if _, ok := seen[SarifRuleID(f)]; !ok {
			seen[SarifRuleID(f)] = f
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rules := []any{}
	for _, id := range ids {
		f := seen[id]
		rules = append(rules, map[string]any{
			"id": id, "name": f.Name,
			"shortDescription": map[string]any{"text": f.Name},
			"help":             map[string]any{"text": f.Fix},
			"properties": map[string]any{
				"tags":              sarifTags(f),
				"security-severity": securitySeverity[f.Severity],
			},
		})
	}
	results := []any{}
	for _, f := range r.Findings {
		results = append(results, map[string]any{
			"ruleId":  SarifRuleID(f),
			"level":   sarifLevel[f.Severity],
			"message": map[string]any{"text": f.Message + "\nFix: " + f.Fix},
			"locations": []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": f.File},
				"region":           map[string]any{"startLine": f.Line},
			}}},
			"partialFingerprints": map[string]any{"riskdebt/v1": f.Fingerprint},
		})
	}
	return map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "riskdebt", "version": r.Version,
				"informationUri": "https://github.com/oriebalzyuot96/riskdebt",
				"rules":          rules,
			}},
			"results": results,
		}},
	}
}
