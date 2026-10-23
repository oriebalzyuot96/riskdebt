// Runs the Go, Node.js and Python CLIs against the shared fixtures and fails if their results differ.
// Usage: node scripts/conformance.mjs
// Set RISKDEBT_PYTHON to override the Python command, e.g. "uv run --python 3.12 python".
//
// It checks, for every fixture: findings (rule, check, severity, file, line), CWE/OWASP tags, fingerprints, skipped
// counts and SARIF. Then it checks that a baseline written by one implementation is read by the others, and that
// --since reports the same lines in a real temporary git repository.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const pyCmd = (process.env.RISKDEBT_PYTHON || (process.platform === 'win32' ? 'python' : 'python3')).split(' ');
const TODAY = ['--today', '2026-10-23'];

const impls = {
  go: ['go', ['run', './cmd/riskdebt']],
  node: ['node', ['node/bin/riskdebt.js']],
  python: [pyCmd[0], [...pyCmd.slice(1), '-m', 'riskdebt']],
};
const env = { ...process.env, PYTHONPATH: path.join(root, 'python', 'src') };

let failed = false;
const fail = (msg) => {
  console.error(msg);
  failed = true;
};

function run(name, args, cwd = root) {
  const [cmd, base] = impls[name];
  // paths in args are resolved against cwd; the Go binary is run from the repo root via `go run`
  const r = spawnSync(cmd, [...base, ...args], { cwd, env, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  return r;
}

// Go has to be started from the repo root; for other working directories use a prebuilt binary.
function runIn(name, dir, args) {
  if (name !== 'go') {
    const [cmd, base] = impls[name];
    const abs = base.map((b) => (b.endsWith('riskdebt.js') ? path.join(root, b) : b));
    return spawnSync(cmd, [...abs, ...args], { cwd: dir, env, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  }
  return spawnSync(goBinary, args, { cwd: dir, env, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

const goBinary = path.join(os.tmpdir(), `riskdebt-conformance-${process.pid}${process.platform === 'win32' ? '.exe' : ''}`);
const build = spawnSync('go', ['build', '-o', goBinary, './cmd/riskdebt'], { cwd: root, encoding: 'utf8' });
if (build.status !== 0) {
  console.error(build.stderr);
  process.exit(1);
}

const ruleId = (f) => (f.check ? `${f.rule}/${f.check}` : f.rule);

// ---------------------------------------------------------------- 1. fixtures
for (const fixture of ['vulnerable-app', 'clean-app', 'ignore-app']) {
  const results = {};
  for (const name of Object.keys(impls)) {
    const r = run(name, [`fixtures/${fixture}`, '--format', 'json', ...TODAY, '--fail-on', 'none']);
    if (r.status !== 0) {
      console.error(`${name} failed on ${fixture}:\n${r.stderr || r.error}`);
      process.exit(1);
    }
    const out = JSON.parse(r.stdout);
    results[name] = [
      `skipped:${out.skipped.dirs}/${out.skipped.files}`,
      ...out.findings.map((f) => `${ruleId(f)}|${f.severity}|${f.file}:${f.line}|${f.cwe.join(',')}|${f.owasp.join(',')}`),
      `fingerprints:${out.findings.map((f) => f.fingerprint).sort().join(',')}`,
    ];
    if (out.findings.some((f) => !f.fix)) fail(`${name}: finding without a fix on ${fixture}`);
    if (out.findings.some((f) => f.cwe.length === 0 || f.owasp.length === 0)) fail(`${name}: finding without CWE/OWASP tags on ${fixture}`);
    if (out.findings.some((f) => !/^[0-9a-f]{20}$/.test(f.fingerprint))) fail(`${name}: bad fingerprint on ${fixture}`);

    const s = run(name, [`fixtures/${fixture}`, '--format', 'sarif', ...TODAY, '--fail-on', 'none']);
    const sarif = JSON.parse(s.stdout);
    const sr = sarif.runs[0].results.map((x) => `${x.ruleId}|${x.locations[0].physicalLocation.artifactLocation.uri}:${x.locations[0].physicalLocation.region.startLine}|${x.partialFingerprints['riskdebt/v1']}`);
    const jr = out.findings.map((f) => `${ruleId(f)}|${f.file}:${f.line}|${f.fingerprint}`);
    if (sarif.version !== '2.1.0' || JSON.stringify(sr) !== JSON.stringify(jr)) fail(`${name}: SARIF output does not match findings on ${fixture}`);
    const tagged = sarif.runs[0].tool.driver.rules.every((x) => x.properties.tags.some((t) => t.startsWith('external/cwe/')) && x.properties['security-severity']);
    if (!tagged) fail(`${name}: SARIF rules are missing CWE tags or security-severity on ${fixture}`);
  }
  const ref = JSON.stringify(results.go);
  for (const name of Object.keys(results)) {
    const same = JSON.stringify(results[name]) === ref;
    console.log(`${fixture.padEnd(15)} ${name.padEnd(7)} ${results[name].length - 2} findings ${same ? 'OK' : 'MISMATCH'}`);
    if (!same) {
      failed = true;
      const a = new Set(results.go);
      const b = new Set(results[name]);
      for (const x of a) if (!b.has(x)) console.error(`  only in go: ${x.slice(0, 160)}`);
      for (const x of b) if (!a.has(x)) console.error(`  only in ${name}: ${x.slice(0, 160)}`);
    }
  }
}

// ---------------------------------------------------------------- 2. baseline written by one, read by all
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'riskdebt-conf-'));
const baselines = {};
for (const name of Object.keys(impls)) {
  const file = path.join(tmp, `baseline-${name}.json`);
  const w = run(name, ['fixtures/vulnerable-app', ...TODAY, '--write-baseline', file]);
  if (w.status !== 0) {
    fail(`${name}: --write-baseline failed: ${w.stderr}`);
    continue;
  }
  baselines[name] = { file, fingerprints: JSON.parse(fs.readFileSync(file, 'utf8')).findings.map((e) => e.fingerprint).sort() };
}
const baseRef = JSON.stringify(baselines.go.fingerprints);
for (const name of Object.keys(baselines)) {
  const same = JSON.stringify(baselines[name].fingerprints) === baseRef;
  console.log(`baseline        ${name.padEnd(7)} ${baselines[name].fingerprints.length} entries ${same ? 'OK' : 'MISMATCH'}`);
  if (!same) failed = true;
}
for (const reader of Object.keys(impls)) {
  for (const writer of Object.keys(baselines)) {
    const r = run(reader, ['fixtures/vulnerable-app', ...TODAY, '--baseline', baselines[writer].file, '--format', 'json', '--fail-on', 'none']);
    const out = JSON.parse(r.stdout);
    const ok = out.findings.length === 0 && out.baselined === baselines[writer].fingerprints.length && out.baselineStale === 0;
    if (!ok) fail(`${reader} reading the baseline written by ${writer}: ${out.findings.length} findings left, ${out.baselined} hidden, ${out.baselineStale} stale`);
  }
}
console.log('baseline        every implementation reads every implementation\'s baseline OK');

// ---------------------------------------------------------------- 3. --since in a real git repository
const repo = path.join(tmp, 'repo');
fs.mkdirSync(path.join(repo, 'src'), { recursive: true });
fs.writeFileSync(path.join(repo, 'src', 'old.js'), 'const a = 1;\neval(oldInput);\nconst b = 2;\n');
fs.writeFileSync(path.join(repo, 'src', 'touched.js'), 'const x = 1;\nconst y = 2;\n');
const git = (...a) => {
  const r = spawnSync('git', ['-C', repo, '-c', 'user.name=t', '-c', 'user.email=t@t', '-c', 'commit.gpgsign=false', ...a], { encoding: 'utf8' });
  if (r.status !== 0) {
    console.error(`git ${a.join(' ')} failed: ${r.stderr}`);
    process.exit(1);
  }
};
git('init', '-q');
git('add', '-A');
git('commit', '-q', '-m', 'base');
// a new vulnerable line in an existing file, a new tracked file, and an untracked file
fs.appendFileSync(path.join(repo, 'src', 'touched.js'), 'eval(newInput);\n');
fs.writeFileSync(path.join(repo, 'src', 'added.js'), 'document.write(userHtml);\n');
git('add', 'src/added.js');
fs.writeFileSync(path.join(repo, 'src', 'untracked.js'), 'const q = 1;\neval(q);\n');
const since = {};
for (const name of Object.keys(impls)) {
  const r = runIn(name, repo, ['.', '--since', 'HEAD', '--format', 'json', ...TODAY, '--fail-on', 'none']);
  if (r.status !== 0) {
    fail(`${name}: --since failed: ${r.stderr}`);
    continue;
  }
  const out = JSON.parse(r.stdout);
  since[name] = out.findings.map((f) => `${ruleId(f)}|${f.file}:${f.line}`);
}
const expected = ['RD008/js-document-write|src/added.js:1', 'RD008/js-eval|src/touched.js:3', 'RD008/js-eval|src/untracked.js:2'];
for (const name of Object.keys(since)) {
  const ok = JSON.stringify([...since[name]].sort()) === JSON.stringify(expected);
  console.log(`--since HEAD    ${name.padEnd(7)} ${since[name].length} findings ${ok ? 'OK' : 'MISMATCH'}`);
  if (!ok) {
    failed = true;
    console.error(`  got      ${JSON.stringify(since[name])}\n  expected ${JSON.stringify(expected)}`);
  }
}
// a bad ref is a clear error, not a silent full report
for (const name of Object.keys(impls)) {
  const r = runIn(name, repo, ['.', '--since', 'no-such-ref', '--fail-on', 'none']);
  if (r.status !== 2 || !/git diff failed/.test(r.stderr)) fail(`${name}: a bad --since ref should exit 2 with a git error (got ${r.status}: ${r.stderr.slice(0, 120)})`);
}

fs.rmSync(tmp, { recursive: true, force: true });
fs.rmSync(goBinary, { force: true });
process.exit(failed ? 1 : 0);
