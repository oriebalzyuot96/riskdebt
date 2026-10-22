const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };

// Converts a scan result to a SARIF 2.1.0 log (for GitHub code scanning).
export function toSarif(r) {
  const seen = new Map();
  for (const f of r.findings) if (!seen.has(f.rule)) seen.set(f.rule, f);
  const rules = [...seen.keys()].sort().map((id) => {
    const f = seen.get(id);
    return { id, name: f.name, shortDescription: { text: f.name }, help: { text: f.fix } };
  });
  const results = r.findings.map((f) => ({
    ruleId: f.rule,
    level: LEVEL[f.severity],
    message: { text: `${f.message}\nFix: ${f.fix}` },
    locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line } } }],
  }));
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'riskdebt', version: r.version, informationUri: 'https://github.com/oriebalzyuot96/riskdebt', rules } },
      results,
    }],
  };
}
