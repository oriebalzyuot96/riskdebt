import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scan } from '../src/scanner.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'fixtures');
const today = Date.parse('2026-10-23');

test('clean app has no findings', () => {
  assert.equal(scan(path.join(root, 'clean-app'), { today }).findings.length, 0);
});

test('vulnerable app: every finding explains the fix', () => {
  const r = scan(path.join(root, 'vulnerable-app'), { today });
  assert.ok(r.findings.length > 20);
  for (const f of r.findings) assert.ok(f.fix && f.fix.length > 10, `${f.rule} ${f.file} has no fix`);
});

test('detects a compromised package and a bypassed Angular sanitizer', () => {
  const r = scan(path.join(root, 'vulnerable-app'), { today });
  assert.ok(r.findings.some((f) => f.rule === 'RD003' && f.message.includes('event-stream')));
  assert.ok(r.findings.some((f) => f.rule === 'RD008' && f.message.includes('[Angular]')));
});
