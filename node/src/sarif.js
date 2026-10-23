const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
// The 0-10 score GitHub code scanning uses to show critical/high/medium/low.
const SECURITY_SEVERITY = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '1.0' };

// The SARIF rule id of a finding: the rule family plus its sub-check, e.g. RD008/react-dangerous-html.
export const sarifRuleId = (f) => (f.check ? `${f.rule}/${f.check}` : f.rule);

const tagsOf = (f) => ['security', ...f.cwe.map((c) => `external/cwe/${c.toLowerCase()}`), ...f.owasp.map((o) => `OWASP-${o}`)];

// Converts a scan result to a SARIF 2.1.0 log (for GitHub code scanning).
export function toSarif(r) {
  const seen = new Map();
  for (const f of r.findings) if (!seen.has(sarifRuleId(f))) seen.set(sarifRuleId(f), f);
  const rules = [...seen.keys()].sort().map((id) => {
    const f = seen.get(id);
    return {
      id,
      name: f.name,
      shortDescription: { text: f.name },
      help: { text: f.fix },
      properties: { tags: tagsOf(f), 'security-severity': SECURITY_SEVERITY[f.severity] },
    };
  });
  const results = r.findings.map((f) => ({
    ruleId: sarifRuleId(f),
    level: LEVEL[f.severity],
    message: { text: `${f.message}\nFix: ${f.fix}` },
    locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line } } }],
    partialFingerprints: { 'riskdebt/v1': f.fingerprint },
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
