// Finds CANDIDATE security problems in published npm packages (default: Angular libraries that render content).
// Candidates are leads for MANUAL review, not vulnerabilities. Read README.md before reporting anything.
//
// It only reads public data: the npm registry, the published package tarballs (unpacked on this computer) and
// whether the source repository has a SECURITY.md. It never contacts a running website or application.
//
// Usage:
//   node scan.mjs --query "keywords:angular markdown" --limit 12
//   node scan.mjs --packages ngx-markdown,ngx-quill
// Options: --riskdebt "<command>"   (default: node ../node/bin/riskdebt.js, else npx riskdebt)
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (name, fallback = '') => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
};
const query = opt('query', 'keywords:angular markdown');
const limit = Number(opt('limit', '12'));
const explicit = opt('packages').split(',').map((s) => s.trim()).filter(Boolean);
// Published libraries ship big bundles (pdf.js: pdf.worker.mjs is over 2 MB); riskdebt's 1 MB default would skip them.
const maxSizeKB = opt('max-size', '8192');
const label = explicit.length ? explicit.join(', ') : query;
const work = path.join(here, 'work');
const reportsDir = path.join(here, 'reports');
fs.mkdirSync(work, { recursive: true });
fs.mkdirSync(reportsDir, { recursive: true });

const localRiskdebt = path.join(here, '..', 'node', 'bin', 'riskdebt.js');
const riskdebtCmd = opt('riskdebt', fs.existsSync(localRiskdebt) ? `node ${localRiskdebt}` : 'npx --yes riskdebt@latest').split(' ');

// What to look at. weight = how much a hit raises a package in the ranking.
const CHECKS = {
  'angular-bypass-sanitizer': { weight: 5, why: 'turns off Angular\'s HTML sanitizer: XSS if the value is not sanitized first' },
  'js-eval': { weight: 4, why: 'runs dynamic code: injection if any part is user-controlled' },
  'js-native-innerhtml': { weight: 2, why: 'writes HTML directly: XSS if the value is not escaped or sanitized first' },
  'js-document-write': { weight: 2, why: 'document.write with dynamic content' },
  'js-token-in-localstorage': { weight: 1, why: 'stores a token where any XSS can read it' },
  'js-tls-disabled': { weight: 3, why: 'turns off TLS certificate checks' },
  'token-in-url': { weight: 1, why: 'secret in a URL' },
  'js-jwt-alg-none': { weight: 4, why: 'accepts unsigned JWTs' },
  'js-jwt-hardcoded-secret': { weight: 4, why: 'JWT signed with a constant key' },
};
const RULE_WEIGHTS = { RD003: 6, RD004: 5 };

const get = async (url) => {
  const r = await fetch(url, { headers: { 'user-agent': 'angular-research-scan (local, read-only)' } });
  if (!r.ok) throw new Error(`${url} -> ${r.status}`);
  return r;
};
const enc = (name) => encodeURIComponent(name).replace('%40', '@');

async function pickPackages() {
  if (explicit.length) return explicit;
  const url = `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(query)}&size=${limit}&popularity=1.0&quality=0.3&maintenance=0.2`;
  const res = await (await get(url)).json();
  return res.objects.map((o) => o.package.name);
}

async function inspect(name) {
  const meta = await (await get(`https://registry.npmjs.org/${enc(name)}`)).json();
  const version = meta['dist-tags']?.latest;
  const v = meta.versions?.[version];
  if (!v) throw new Error('no latest version');
  let downloads = null;
  try {
    downloads = (await (await get(`https://api.npmjs.org/downloads/point/last-week/${enc(name)}`)).json()).downloads;
  } catch { /* optional */ }
  const repo = (v.repository?.url || meta.repository?.url || '').replace(/^git\+/, '').replace(/\.git$/, '').replace(/^git:\/\//, 'https://');
  return { name, version, downloads, repo, homepage: v.homepage, deprecated: !!v.deprecated, tarball: v.dist.tarball };
}

function unpack(info) {
  const dir = path.join(work, info.name.replace(/[@/]/g, '_') + '@' + info.version);
  if (fs.existsSync(path.join(dir, 'package'))) return dir;
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

async function download(info, dir) {
  if (fs.existsSync(path.join(dir, 'package'))) return;
  const file = path.join(dir, 'pkg.tgz');
  fs.writeFileSync(file, Buffer.from(await (await get(info.tarball)).arrayBuffer()));
  // Run from inside dir with relative names: GNU tar reads "C:\..." as a remote host called "C".
  const r = spawnSync('tar', ['-xzf', 'pkg.tgz'], { cwd: dir, encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`tar failed: ${r.stderr}`);
  fs.rmSync(file);
  // riskdebt skips folders named dist/build/out; published libraries often keep their code there, so rename them.
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (!e.isDirectory()) continue;
      const p = path.join(d, e.name);
      if (['dist', 'build', 'out'].includes(e.name)) {
        fs.renameSync(p, path.join(d, `_${e.name}`));
        walk(path.join(d, `_${e.name}`));
      } else walk(p);
    }
  };
  walk(path.join(dir, 'package'));
}

function scan(dir) {
  const [cmd, ...pre] = riskdebtCmd;
  const r = spawnSync(cmd, [...pre, path.join(dir, 'package'), '--format', 'json', '--fail-on', 'none', '--no-gitignore', '--max-size', maxSizeKB], {
    encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, shell: process.platform === 'win32' && cmd === 'npx',
  });
  if (r.status !== 0) throw new Error(`riskdebt failed: ${(r.stderr || '').slice(0, 200)}`);
  return JSON.parse(r.stdout);
}

function snippet(dir, finding) {
  try {
    const lines = fs.readFileSync(path.join(dir, 'package', finding.file), 'utf8').split('\n');
    const a = Math.max(0, finding.line - 4), b = Math.min(lines.length, finding.line + 3);
    return lines.slice(a, b).map((l, i) => `${String(a + i + 1).padStart(5)}${a + i + 1 === finding.line ? ' >' : '  '} ${l.replace(/\r$/, '').slice(0, 170)}`).join('\n');
  } catch {
    return '(could not read the file)';
  }
}

async function hasSecurityPolicy(repo) {
  const m = repo.match(/github\.com[/:]([^/]+)\/([^/#?]+)/);
  if (!m) return 'unknown (no GitHub repository listed)';
  const r = spawnSync('gh', ['api', `repos/${m[1]}/${m[2]}/contents/SECURITY.md`, '--jq', '.name'], { encoding: 'utf8' });
  if (r.status === 0) return 'yes, SECURITY.md exists (follow it)';
  const adv = spawnSync('gh', ['api', `repos/${m[1]}/${m[2]}`, '--jq', '.security_and_analysis // empty'], { encoding: 'utf8' });
  return adv.status === 0 ? 'no SECURITY.md; try GitHub "Report a vulnerability" on the Security tab, else a private email to the maintainer' : 'unknown';
}

// Noise filters: tests are not shipped behaviour, and assigning a fixed string to innerHTML cannot carry user data.
const TEST_PATH = /(^|[/\\])(__tests__|tests?|specs?|__mocks__|fixtures?)([/\\]|$)|\.(test|spec)\.[cm]?[jt]s$/i;
function isConstantAssignment(dir, f) {
  if (f.check !== 'js-native-innerhtml') return false;
  try {
    const text = fs.readFileSync(path.join(dir, 'package', f.file), 'utf8').split('\n');
    const rest = text.slice(f.line - 1, f.line + 40).join('\n');
    const m = rest.match(/\.(?:innerHTML|outerHTML)\s*=\s*(['"`])/);
    if (!m) return false;
    const start = rest.indexOf(m[0]) + m[0].length;
    const end = rest.indexOf(m[1], start);
    return end > start - 1 && !rest.slice(start, end).includes('${');
  } catch {
    return false;
  }
}

const names = await pickPackages();
console.log(`Scanning ${names.length} packages: ${names.join(', ')}`);
const results = [];
for (const name of names) {
  try {
    const info = await inspect(name);
    const dir = unpack(info);
    await download(info, dir);
    const out = scan(dir);
    const leads = out.findings.filter((f) => ((f.rule === 'RD008' && CHECKS[f.check]) || RULE_WEIGHTS[f.rule]) && !TEST_PATH.test(f.file) && !isConstantAssignment(dir, f));
    const score = leads.reduce((s, f) => s + (RULE_WEIGHTS[f.rule] || CHECKS[f.check].weight), 0);
    results.push({ info, dir, scanned: out.scanned, leads, score });
    console.log(`  ${name}@${info.version}: ${out.scanned} files, ${leads.length} leads (score ${score})`);
  } catch (err) {
    console.log(`  ${name}: skipped (${err.message})`);
    results.push({ info: { name, version: '?' }, error: err.message, leads: [], score: -1 });
  }
}

results.sort((a, b) => b.score - a.score);
const md = [];
md.push(`# Candidate review list: ${label}`, '', `Generated ${new Date().toISOString().slice(0, 10)} by scan.mjs. **These are leads, not vulnerabilities.** Each one needs manual triage (is the value user-controlled? is it sanitized earlier?) and a local proof of concept before anything is reported.`, '');
md.push('| Package | Version | Weekly downloads | Leads | Score |', '|---|---|---|---|---|');
for (const r of results) md.push(`| ${r.info.name} | ${r.info.version} | ${r.info.downloads ?? '?'} | ${r.leads.length} | ${r.error ? 'error' : r.score} |`);
md.push('');
for (const r of results.filter((x) => x.leads.length)) {
  md.push(`## ${r.info.name}@${r.info.version}`, '');
  md.push(`- Repository: ${r.info.repo || 'not listed'}`, `- Weekly downloads: ${r.info.downloads ?? '?'}${r.info.deprecated ? ' (DEPRECATED)' : ''}`);
  md.push(`- Reporting channel: ${await hasSecurityPolicy(r.info.repo || '')}`, '');
  const byFile = new Map();
  for (const f of r.leads) {
    const k = `${f.rule}/${f.check || ''}`;
    if (!byFile.has(k)) byFile.set(k, []);
    byFile.get(k).push(f);
  }
  for (const [k, list] of byFile) {
    const why = CHECKS[list[0].check]?.why || list[0].message;
    md.push(`### ${k}: ${list.length} hit(s), ${why}`, '');
    for (const f of list.slice(0, 4)) md.push(`\`${f.file}:${f.line}\``, '```', snippet(r.dir, f), '```', '');
    if (list.length > 4) md.push(`...and ${list.length - 4} more`, '');
  }
}
const stamp = new Date().toISOString().slice(0, 10);
const file = path.join(reportsDir, `candidates-${label.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}-${stamp}.md`);
fs.writeFileSync(file, md.join('\n') + '\n');
console.log(`\nReport: ${file}`);
