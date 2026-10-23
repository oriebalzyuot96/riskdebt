import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/scanner.js';
import { applyBaseline, newBaseline } from '../src/baseline.js';
import { toSarif } from '../src/sarif.js';

const fixtures = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'fixtures');
const today = Date.parse('2026-10-23');
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'riskdebt-test-'));

test('every finding is tagged with CWE and OWASP ids', () => {
  const r = scan(path.join(fixtures, 'vulnerable-app'), { today });
  for (const f of r.findings) {
    assert.ok(f.cwe.length > 0 && f.owasp.length > 0, `${f.rule} ${f.file}:${f.line} has no tags`);
    assert.ok(f.cwe.every((c) => c.startsWith('CWE-')));
  }
});

test('workflow hardening finds each risky pattern and leaves the safe env: step alone', () => {
  const r = scan(path.join(fixtures, 'vulnerable-app'), { today });
  const got = {};
  for (const f of r.findings.filter((x) => x.rule === 'RD009')) {
    got[f.check] = (got[f.check] || 0) + 1;
    if (f.file.endsWith('risky.yml')) assert.ok(f.line < 19, `the safe step was flagged at line ${f.line}`);
  }
  assert.deepEqual(got, { 'missing-permissions': 1, 'write-all-permissions': 1, 'pwn-request': 1, 'script-injection': 2, 'curl-pipe-shell': 1 });
});

test('a fingerprint survives line shifts but not edits to the offending line', () => {
  const dir = tmp();
  const file = path.join(dir, 'a.js');
  fs.writeFileSync(file, 'const a = 1;\neval(userInput);\n');
  const before = scan(dir, { today }).findings[0];
  fs.writeFileSync(file, '// new\n// comment\n\nconst a = 1;\neval(userInput);\n');
  const shifted = scan(dir, { today }).findings[0];
  assert.notEqual(shifted.line, before.line);
  assert.equal(shifted.fingerprint, before.fingerprint);
  fs.writeFileSync(file, 'const a = 1;\neval(otherInput);\n');
  assert.notEqual(scan(dir, { today }).findings[0].fingerprint, before.fingerprint);
});

test('identical findings get distinct fingerprints', () => {
  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'a.js'), 'eval(x);\neval(x);\n');
  const f = scan(dir, { today }).findings;
  assert.equal(f.length, 2);
  assert.notEqual(f[0].fingerprint, f[1].fingerprint);
});

test('a baseline hides known findings, counts stale entries and keeps new ones', () => {
  const r = scan(path.join(fixtures, 'vulnerable-app'), { today });
  const total = r.findings.length;
  const b = newBaseline(r);
  b.findings.push({ fingerprint: 'deadbeefdeadbeefdead', rule: 'RD001', file: 'gone.json', line: 1 });
  const again = scan(path.join(fixtures, 'vulnerable-app'), { today });
  applyBaseline(again, b);
  assert.deepEqual([again.findings.length, again.baselined, again.baselineStale], [0, total, 1]);

  const dir = tmp();
  fs.writeFileSync(path.join(dir, 'a.js'), 'eval(a);\n');
  const base = newBaseline(scan(dir, { today }));
  fs.writeFileSync(path.join(dir, 'a.js'), 'eval(a);\ndocument.write(b);\n');
  const next = scan(dir, { today });
  applyBaseline(next, base);
  assert.deepEqual(next.findings.map((f) => f.check), ['js-document-write']);
});

test('SARIF rule ids include the check and every rule has a CWE tag and security-severity', () => {
  const sarif = toSarif(scan(path.join(fixtures, 'vulnerable-app'), { today }));
  const rules = sarif.runs[0].tool.driver.rules;
  const ids = rules.map((x) => x.id);
  for (const want of ['RD008/react-dangerous-html', 'RD009/pwn-request', 'RD003']) assert.ok(ids.includes(want), `missing ${want}`);
  for (const r of rules) {
    assert.ok(r.properties.tags.some((t) => t.startsWith('external/cwe/cwe-')), `${r.id} has no CWE tag`);
    assert.ok(r.properties['security-severity']);
  }
});
