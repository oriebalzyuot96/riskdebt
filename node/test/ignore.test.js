import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { matches, parseIgnoreLine } from '../src/ignore.js';

const casesFile = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'fixtures', 'ignore-cases.json');

// The same cases drive the Go and Python tests, so the three matchers cannot drift apart.
test('ignore matcher agrees with the shared cases', () => {
  for (const c of JSON.parse(fs.readFileSync(casesFile, 'utf8'))) {
    const rule = parseIgnoreLine(c.pattern);
    const got = rule !== null && matches(rule, c.rel, path.posix.basename(c.rel), c.isDir);
    assert.equal(got, c.want, `pattern ${JSON.stringify(c.pattern)} vs ${c.rel} (dir=${c.isDir})`);
  }
});
