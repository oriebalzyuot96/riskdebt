package scanner

import "sort"

var sarifLevel = map[string]string{"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}

// SARIF converts a result to a SARIF 2.1.0 log (for GitHub code scanning).
func SARIF(r *Result) map[string]any {
	seen := map[string]Finding{}
	for _, f := range r.Findings {
		if _, ok := seen[f.Rule]; !ok {
			seen[f.Rule] = f
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
		})
	}
	results := []any{}
	for _, f := range r.Findings {
		results = append(results, map[string]any{
			"ruleId":  f.Rule,
			"level":   sarifLevel[f.Severity],
			"message": map[string]any{"text": f.Message + "\nFix: " + f.Fix},
			"locations": []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": f.File},
				"region":           map[string]any{"startLine": f.Line},
			}}},
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
