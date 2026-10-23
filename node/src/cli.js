import fs from 'node:fs';
import path from 'node:path';
import { scan, rank, VERSION } from './scanner.js';
import { toSarif } from './sarif.js';
import { DEFAULT_BASELINE_FILE, applyBaseline, filterSince, loadBaseline, newBaseline } from './baseline.js';

const USAGE = `riskdebt - find the security debt hiding in your project

Usage: riskdebt [path] [options]

Options:
  -f, --format <text|json|sarif>   output format (default text)
      --fail-on <severity>   exit 1 at or above: critical|high|medium|low|none (default high)
      --today <YYYY-MM-DD>   override today's date (for reproducible EOL checks)
      --blocklist <file>     extra compromised-package list (JSON)
      --exclude <pattern>    skip paths, .gitignore-style (repeatable); also reads .riskdebtignore
      --no-gitignore         do not read .gitignore (it is honoured by default)
      --max-size <KB>        skip files larger than this (default 1024)
      --since <git-ref>      only report findings on lines changed since this ref (what a pull request adds)
      --write-baseline <file>  save every current finding as known, then exit 0
      --baseline <file>      hide the findings listed in this baseline (default: .riskdebt-baseline.json if present)
      --no-baseline          ignore the default baseline file
  -v, --version              print version
  -h, --help                 show this help
`;

const die = (msg) => {
  process.stderr.write(`riskdebt: ${msg}\n`);
  process.exit(2);
};

export function main(argv) {
  let root = '.';
  let format = 'text';
  let failOn = 'high';
  let since = '';
  let baselinePath = '';
  let writeBaseline = '';
  let noBaseline = false;
  const opts = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) die(`missing value for ${a}`);
      return argv[++i];
    };
    switch (a) {
      case '-h':
      case '--help':
        process.stdout.write(USAGE);
        return;
      case '-v':
      case '--version':
        console.log(VERSION);
        return;
      case '-f':
      case '--format':
        format = next();
        break;
      case '--fail-on':
        failOn = next();
        break;
      case '--today': {
        const v = next();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(v) || Number.isNaN(Date.parse(v))) die('--today must be YYYY-MM-DD');
        opts.today = Date.parse(v);
        break;
      }
      case '--exclude':
        (opts.exclude ||= []).push(next());
        break;
      case '--no-gitignore':
        opts.noGitignore = true;
        break;
      case '--max-size': {
        const kb = Number(next());
        if (!Number.isInteger(kb) || kb <= 0) die('--max-size must be a positive number of KB');
        opts.maxSizeKB = kb;
        break;
      }
      case '--since':
        since = next();
        break;
      case '--baseline':
        baselinePath = next();
        break;
      case '--write-baseline':
        writeBaseline = next();
        break;
      case '--no-baseline':
        noBaseline = true;
        break;
      case '--blocklist':
        try {
          opts.extraBlocklist = JSON.parse(fs.readFileSync(next(), 'utf8'));
        } catch (err) {
          die(`bad blocklist: ${err.message}`);
        }
        break;
      default:
        if (a.startsWith('-')) die(`unknown option ${a}`);
        root = a;
    }
  }
  if (!['text', 'json', 'sarif'].includes(format)) die('--format must be text, json or sarif');
  if (failOn !== 'none' && rank(failOn) < 0) die('--fail-on must be critical|high|medium|low|none');
  if (writeBaseline && (since || baselinePath)) die('--write-baseline records the full scan; do not combine it with --since or --baseline');

  const res = scan(root, opts);

  if (writeBaseline) {
    fs.writeFileSync(writeBaseline, JSON.stringify(newBaseline(res), null, 2) + '\n');
    console.log(`Baseline written: ${res.findings.length} findings -> ${writeBaseline}`);
    return;
  }
  try {
    if (!noBaseline) {
      let file = baselinePath;
      if (!file) {
        const def = path.join(root, DEFAULT_BASELINE_FILE);
        if (fs.existsSync(def) && fs.statSync(def).isFile()) file = def;
      }
      if (file) applyBaseline(res, loadBaseline(file));
    }
    if (since) filterSince(res, root, since);
  } catch (err) {
    die(err.message);
  }

  if (format === 'sarif') console.log(JSON.stringify(toSarif(res), null, 2));
  else if (format === 'json') console.log(JSON.stringify(res, null, 2));
  else printText(res);
  if (failOn !== 'none' && res.findings.some((f) => rank(f.severity) >= rank(failOn))) process.exitCode = 1;
}

function printText(r) {
  const color = process.stdout.isTTY && !process.env.NO_COLOR;
  const paint = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const colors = { critical: '1;31', high: '31', medium: '33', low: '36', info: '2' };
  console.log(`riskdebt ${r.version} - scanned ${r.scanned} files in ${r.root} (skipped ${r.skipped.dirs} folders, ${r.skipped.files} files: ignored, binary or too large)`);
  if (r.since) console.log(`diff-only: findings on lines changed since ${r.since}`);
  if (r.baselined > 0 || r.baselineStale > 0) {
    let line = `baseline: ${r.baselined} known findings hidden`;
    if (r.baselineStale > 0) line += `, ${r.baselineStale} entries no longer match (refresh with --write-baseline)`;
    console.log(line);
  }
  console.log('');
  for (const f of r.findings) {
    const tags = [...f.cwe, ...f.owasp];
    console.log(`${paint(colors[f.severity], f.severity.toUpperCase().padEnd(8))} ${f.rule}  ${f.file}:${f.line}${tags.length ? `  [${tags.join(' · ')}]` : ''}`);
    console.log(`  problem: ${f.message}`);
    console.log(`  fix:     ${f.fix}\n`);
  }
  const s = r.summary;
  console.log(`${r.findings.length} findings: ${s.critical} critical, ${s.high} high, ${s.medium} medium, ${s.low} low`);
}
