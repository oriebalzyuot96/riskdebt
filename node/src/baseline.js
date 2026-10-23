// Fingerprints, baselines and --since filtering. Must behave exactly like internal/scanner/baseline.go and
// python/src/riskdebt/baseline.py, so a baseline file written by one implementation works with the others.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { VERSION } from './scanner.js';

export const DEFAULT_BASELINE_FILE = '.riskdebt-baseline.json';

const normalizeWS = (s) => s.split(/\s+/).filter(Boolean).join(' ');

// Gives each finding an id built from the rule, the file and the text of the offending line (not its number), so a
// finding keeps its id when lines above it are added or removed. Findings that share all three get an occurrence
// index. findings must already be sorted.
export function fingerprintAll(findings, root) {
  const byFile = new Map();
  for (const f of findings) {
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file).push(f);
  }
  for (const [file, list] of byFile) {
    let lines = [];
    try {
      lines = fs.readFileSync(path.join(root, file), 'utf8').split('\n');
    } catch {
      // unreadable: fingerprint without the line text
    }
    const seen = new Map();
    for (const f of list) {
      const lt = f.line >= 1 && f.line <= lines.length ? normalizeWS(lines[f.line - 1]) : '';
      const base = `${f.rule}\0${file}\0${lt}`;
      const n = seen.get(base) || 0;
      seen.set(base, n + 1);
      f.fingerprint = crypto.createHash('sha256').update(`${base}\0${n}`).digest('hex').slice(0, 20);
    }
  }
}

export function newBaseline(result) {
  const findings = result.findings.map((f) => ({ fingerprint: f.fingerprint, rule: f.rule, file: f.file, line: f.line }));
  const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  findings.sort((x, y) => cmp(x.file, y.file) || x.line - y.line || cmp(x.rule, y.rule) || cmp(x.fingerprint, y.fingerprint));
  return { version: 1, tool: 'riskdebt', toolVersion: VERSION, findings };
}

export function loadBaseline(file) {
  let b;
  try {
    b = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    throw new Error(`bad baseline ${file}: ${err.message}`);
  }
  if (b.version !== 1) throw new Error(`baseline ${file} has unsupported version ${b.version}`);
  return b;
}

export function summarize(findings) {
  const s = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) s[f.severity]++;
  return s;
}

// Hides the findings that are in the baseline and counts baseline entries that match nothing now.
export function applyBaseline(result, baseline) {
  const known = new Set(baseline.findings.map((e) => e.fingerprint));
  const current = new Set(result.findings.map((f) => f.fingerprint));
  const kept = result.findings.filter((f) => !known.has(f.fingerprint));
  result.baselined += result.findings.length - kept.length;
  result.baselineStale += baseline.findings.filter((e) => !current.has(e.fingerprint)).length;
  result.findings = kept;
  result.summary = summarize(kept);
}

function runGit(root, args) {
  const r = spawnSync('git', ['-C', root, '-c', 'core.quotepath=false', ...args], { encoding: 'utf8', maxBuffer: 512 * 1024 * 1024 });
  if (r.status !== 0) throw new Error(`git ${args[0]} failed: ${(r.stderr || r.error?.message || '').trim()}`);
  return r.stdout;
}

// Per file (relative to root): the lines added or changed since ref in the working tree. Untracked files count in full.
function changedLines(root, ref) {
  if (ref.startsWith('-')) throw new Error(`--since needs a git ref, got "${ref}"`);
  const diff = runGit(root, ['diff', '--relative', '-U0', '--no-color', '--no-ext-diff', '--no-renames', ref, '--']);
  const changed = new Map();
  let cur = '';
  for (const raw of diff.split('\n')) {
    const l = raw.replace(/\r+$/, '');
    if (l.startsWith('+++ ')) {
      let p = l.slice(4);
      const tab = p.indexOf('\t');
      if (tab >= 0) p = p.slice(0, tab);
      if (p === '/dev/null') cur = '';
      else {
        cur = p.startsWith('b/') ? p.slice(2) : p;
        if (!changed.has(cur)) changed.set(cur, { all: false, ranges: [] });
      }
    } else if (l.startsWith('@@') && cur) {
      const i = l.indexOf(' +');
      if (i < 0) continue;
      let rest = l.slice(i + 2);
      const sp = rest.indexOf(' ');
      if (sp >= 0) rest = rest.slice(0, sp);
      const [a, b] = rest.split(',');
      const start = parseInt(a, 10);
      const count = b === undefined ? 1 : parseInt(b, 10);
      if (count > 0) changed.get(cur).ranges.push([start, start + count - 1]);
    }
  }
  for (const p of runGit(root, ['ls-files', '--others', '--exclude-standard']).split('\n')) {
    const q = p.replace(/\r+$/, '');
    if (q) changed.set(q, { all: true, ranges: [] });
  }
  return changed;
}

// Keeps only findings on lines that changed since the git ref (plus file-level findings, reported on line 1, of files
// that changed at all). This is what a pull request adds.
export function filterSince(result, root, ref) {
  const changed = changedLines(root, ref);
  const kept = result.findings.filter((f) => {
    const c = changed.get(f.file);
    return c && (f.line === 1 || c.all || c.ranges.some(([a, b]) => f.line >= a && f.line <= b));
  });
  result.findings = kept;
  result.summary = summarize(kept);
  result.since = ref;
}
