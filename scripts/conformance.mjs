// Runs the Go, Node.js and Python CLIs against the shared fixtures and fails if
// their findings differ. Usage: node scripts/conformance.mjs
// Set RISKDEBT_PYTHON to override the Python command, e.g. "uv run --python 3.12 python".
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const pyCmd = (process.env.RISKDEBT_PYTHON || (process.platform === 'win32' ? 'python' : 'python3')).split(' ');

const impls = {
  go: ['go', ['run', './cmd/riskdebt']],
  node: ['node', ['node/bin/riskdebt.js']],
  python: [pyCmd[0], [...pyCmd.slice(1), '-m', 'riskdebt']],
};

let failed = false;
for (const fixture of ['vulnerable-app', 'clean-app']) {
  const results = {};
  for (const [name, [cmd, base]] of Object.entries(impls)) {
    const env = { ...process.env, PYTHONPATH: path.join(root, 'python', 'src') };
    const r = spawnSync(cmd, [...base, `fixtures/${fixture}`, '--format', 'json', '--today', '2026-10-23', '--fail-on', 'none'], {
      cwd: root,
      env,
      encoding: 'utf8',
    });
    if (r.status !== 0) {
      console.error(`${name} failed on ${fixture}:\n${r.stderr || r.error}`);
      process.exit(1);
    }
    const out = JSON.parse(r.stdout);
    results[name] = out.findings.map((f) => `${f.rule}|${f.severity}|${f.file}:${f.line}`);
    const s = spawnSync(cmd, [...base, `fixtures/${fixture}`, '--format', 'sarif', '--today', '2026-10-23', '--fail-on', 'none'], { cwd: root, env, encoding: 'utf8' });
    const sarif = JSON.parse(s.stdout);
    const sr = sarif.runs[0].results.map((x) => `${x.ruleId}|${x.locations[0].physicalLocation.artifactLocation.uri}:${x.locations[0].physicalLocation.region.startLine}`);
    const jr = out.findings.map((f) => `${f.rule}|${f.file}:${f.line}`);
    if (sarif.version !== '2.1.0' || JSON.stringify(sr) !== JSON.stringify(jr)) {
      console.error(`${name}: SARIF output does not match findings on ${fixture}`);
      failed = true;
    }
    if (out.findings.some((f) => !f.fix)) {
      console.error(`${name}: finding without a fix on ${fixture}`);
      failed = true;
    }
  }
  const ref = JSON.stringify(results.go);
  for (const name of Object.keys(results)) {
    const same = JSON.stringify(results[name]) === ref;
    console.log(`${fixture.padEnd(15)} ${name.padEnd(7)} ${results[name].length} findings ${same ? 'OK' : 'MISMATCH'}`);
    if (!same) {
      failed = true;
      const a = new Set(results.go);
      const b = new Set(results[name]);
      for (const x of a) if (!b.has(x)) console.error(`  only in go: ${x}`);
      for (const x of b) if (!a.has(x)) console.error(`  only in ${name}: ${x}`);
    }
  }
}
process.exit(failed ? 1 : 0);
