import fs from 'node:fs';
import { scan, rank, VERSION } from './scanner.js';
import { toSarif } from './sarif.js';

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

  const res = scan(root, opts);
  if (format === 'sarif') console.log(JSON.stringify(toSarif(res), null, 2));
  else if (format === 'json') console.log(JSON.stringify(res, null, 2));
  else printText(res);
  if (failOn !== 'none' && res.findings.some((f) => rank(f.severity) >= rank(failOn))) process.exitCode = 1;
}

function printText(r) {
  const color = process.stdout.isTTY && !process.env.NO_COLOR;
  const paint = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const colors = { critical: '1;31', high: '31', medium: '33', low: '36', info: '2' };
  console.log(`riskdebt ${r.version} - scanned ${r.scanned} files in ${r.root} (skipped ${r.skipped.dirs} folders, ${r.skipped.files} files: ignored, binary or too large)\n`);
  for (const f of r.findings) {
    console.log(`${paint(colors[f.severity], f.severity.toUpperCase().padEnd(8))} ${f.rule}  ${f.file}:${f.line}`);
    console.log(`  problem: ${f.message}`);
    console.log(`  fix:     ${f.fix}\n`);
  }
  const s = r.summary;
  console.log(`${r.findings.length} findings: ${s.critical} critical, ${s.high} high, ${s.medium} medium, ${s.low} low`);
}
