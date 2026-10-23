import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isWordy, lastQuoted } from '../src/scanner.js';

const casesFile = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'fixtures', 'wordy-cases.json');

// The same cases drive the Go and Python tests, so the three implementations cannot drift apart.
test('isWordy agrees with the shared cases', () => {
  for (const c of JSON.parse(fs.readFileSync(casesFile, 'utf8'))) {
    assert.equal(isWordy(c.value), c.want, `isWordy(${JSON.stringify(c.value)})`);
  }
});

test('lastQuoted returns the text of the last quoted string', () => {
  assert.equal(lastQuoted('token: "abc_def_ghi"'), 'abc_def_ghi');
  assert.equal(lastQuoted(`"refreshToken": 'users/RefreshToken'`), 'users/RefreshToken');
});
