// riskdebt scanner (Node.js). Behaviour must stay identical to the Go and Python
// ports; scripts/conformance.mjs enforces that against shared fixtures.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const VERSION = '0.1.1';

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
export const rank = (s) => (s in SEVERITY_RANK ? SEVERITY_RANK[s] : -1);

const here = path.dirname(fileURLToPath(import.meta.url));

function rulesDir() {
  const candidates = [process.env.RISKDEBT_RULES, path.join(here, '..', 'rules'), path.join(here, '..', '..', 'rules')];
  for (const c of candidates) {
    if (c && fs.existsSync(path.join(c, 'meta.json'))) return c;
  }
  throw new Error('riskdebt: cannot find rules directory');
}

const loadJSON = (dir, name) => JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'));
const compile = (p, flags = '') => new RegExp(p, flags.includes('i') ? 'i' : '');

const SKIP_DIRS = new Set(['.git', 'node_modules', 'vendor', 'dist', 'build', '__pycache__', '.venv', 'venv', 'target', 'bin', 'obj']);
const BINARY_EXTS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.pdf', '.zip', '.gz', '.tar', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.exe', '.dll', '.so', '.wasm']);
const MAX_FILE_SIZE = 1 << 20;

const extOf = (base) => {
  const i = base.lastIndexOf('.');
  return i < 0 ? '' : base.slice(i).toLowerCase();
};
const lines = (text) => text.split('\n');
const findLine = (text, needle) => {
  const ls = lines(text);
  for (let i = 0; i < ls.length; i++) if (ls[i].includes(needle)) return i + 1;
  return 1;
};
const findKeyLine = (text, key) => {
  const q = `"${key}"`;
  const ls = lines(text);
  for (let i = 0; i < ls.length; i++) {
    const idx = ls[i].indexOf(q);
    if (idx >= 0 && ls[i].slice(idx + q.length).replace(/^[ \t]+/, '').startsWith(':')) return i + 1;
  }
  return 1;
};
const endsWithPath = (rel, p) => rel === p || rel.endsWith('/' + p);
const normalizeName = (eco, name) => {
  name = name.toLowerCase();
  return eco === 'pypi' ? name.replace(/[_.]/g, '-') : name;
};
const stripVer = (spec) => spec.replace(/^[\^~=<>v ]+/, '');
const asObj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
const parseJSON = (text) => {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
};

function classifyNpmSpec(spec) {
  if (['workspace:', 'file:', 'link:', 'npm:'].some((p) => spec.startsWith(p))) return '';
  if (['latest', '*', '', 'x'].includes(spec)) return 'high';
  if (['git+', 'git:', 'http:', 'https:', 'github:'].some((p) => spec.startsWith(p))) return 'high';
  if ('^~><'.includes(spec[0]) || spec.includes('*') || spec.endsWith('.x') || spec.includes('||') || spec.includes(' - ')) return 'medium';
  return '';
}

const RE_REQ_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*/;
const RE_NUGET = /<PackageReference\s+Include="([^"]+)"[^>]*?\sVersion="([^"]*)"/;
const RE_NODE = /^v?(\d+)/;
const RE_MAJMIN = /^(\d+)\.(\d+)/;
const RE_PY_RT = /python-(\d+)\.(\d+)/;
const RE_FROM = /^\s*FROM\s+(?:--\S+\s+)*(node|php|python):v?(\d+)(?:\.(\d+))?/i;
const RE_USES = /^\s*-?\s*uses:\s*['"]?([^\s'"#]+)/;
const RE_SHA = /^[0-9a-f]{40}$/;

class Engine {
  constructor(opts) {
    const dir = rulesDir();
    this.meta = loadJSON(dir, 'meta.json');
    const sf = loadJSON(dir, 'secrets.json');
    this.placeholders = sf.placeholders;
    this.secrets = sf.patterns.map((r) => ({ ...r, re: compile(r.pattern, r.flags) }));
    this.patterns = loadJSON(dir, 'patterns.json').map((r) => ({ ...r, re: compile(r.pattern, r.flags) }));
    this.cycles = loadJSON(dir, 'eol.json').cycles;
    this.blocklist = [...loadJSON(dir, 'compromised.json'), ...(opts.extraBlocklist || [])];
    this.today = opts.today;
    this.files = new Set();
    this.findings = [];
  }

  add(rule, severity, file, line, message, fix = '') {
    this.findings.push({ rule, name: this.meta[rule].name, severity, file, line, message, fix: fix || this.meta[rule].fix });
  }

  isPlaceholder(m) {
    const lm = m.toLowerCase();
    return this.placeholders.some((p) => lm.includes(p));
  }

  checkCompromised(eco, name, version, file, line) {
    const n = normalizeName(eco, name);
    for (const b of this.blocklist) {
      if (b.ecosystem !== eco || normalizeName(eco, b.name) !== n) continue;
      if (b.versions.includes(version)) {
        this.add('RD003', 'critical', file, line, `${name}@${version} is a known-compromised release: ${b.reason}`);
        return;
      }
    }
  }

  checkPackageJSON(rel, text) {
    const pj = parseJSON(text);
    if (!pj || typeof pj !== 'object') return;
    let count = 0;
    for (const sec of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      const m = asObj(pj[sec]);
      for (const name of Object.keys(m).sort()) {
        const spec = m[name];
        if (typeof spec !== 'string') continue;
        count++;
        const line = findKeyLine(text, name);
        const c = classifyNpmSpec(spec);
        if (c === 'high') this.add('RD001', 'high', rel, line, `"${name}" uses "${spec}", which can resolve to unreviewed or attacker-controlled code`);
        else if (c === 'medium') this.add('RD001', 'medium', rel, line, `"${name}" uses the range "${spec}"; a hijacked release would be pulled in automatically`);
        this.checkCompromised('npm', name, stripVer(spec), rel, line);
      }
    }
    if (count > 0) {
      const dir = path.posix.dirname(rel);
      const has = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'bun.lock'].some((lf) => this.files.has(path.posix.join(dir, lf)));
      if (!has) this.add('RD002', 'medium', rel, 1, 'package.json has dependencies but no lockfile is committed');
    }
  }

  checkPackageLock(rel, text) {
    const pl = parseJSON(text);
    const pkgs = asObj(pl && pl.packages);
    for (const k of Object.keys(pkgs).sort()) {
      if (k === '') continue;
      const i = k.lastIndexOf('node_modules/');
      const name = i >= 0 ? k.slice(i + 'node_modules/'.length) : k;
      const v = asObj(pkgs[k]).version;
      if (typeof v === 'string') this.checkCompromised('npm', name, v, rel, findLine(text, `"${k}"`));
    }
  }

  checkRequirements(rel, text) {
    let hasDep = false;
    lines(text).forEach((raw, i) => {
      let line = raw.trim().replace(/\\+$/, '').trim();
      if (line === '' || line.startsWith('#') || line.startsWith('-') || line.startsWith('git+') || line.startsWith('http') || line.includes(' @ ')) return;
      let k = line.indexOf(' #');
      if (k >= 0) line = line.slice(0, k).trim();
      k = line.indexOf(';');
      if (k >= 0) line = line.slice(0, k).trim();
      const m = line.match(RE_REQ_NAME);
      if (!m) return;
      hasDep = true;
      k = line.indexOf('==');
      if (k >= 0) {
        const ver = line.slice(k + 2).trim().replace(/^=+/, '').trim();
        this.checkCompromised('pypi', m[0], ver, rel, i + 1);
      } else {
        this.add('RD001', 'medium', rel, i + 1, `"${m[0]}" is not pinned with ==; installs can silently change`);
      }
    });
    if (hasDep && !text.includes('--hash=')) this.add('RD002', 'low', rel, 1, 'requirements file has no --hash entries, so artifacts are not verified');
  }

  checkCsproj(rel, text) {
    lines(text).forEach((l, i) => {
      const m = l.match(RE_NUGET);
      if (m && (m[2].includes('*') || m[2].includes(','))) {
        this.add('RD001', 'medium', rel, i + 1, `NuGet package "${m[1]}" uses the floating version "${m[2]}"`,
          'Pin an exact version, enable lock files (<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>) and restore with --locked-mode.');
      }
    });
  }

  checkSecrets(rel, text) {
    lines(text).forEach((l, i) => {
      if (l.includes('riskdebt-ignore')) return;
      for (const r of this.secrets) {
        const m = l.match(r.re);
        if (!m) continue;
        if (r.skipPlaceholders && this.isPlaceholder(m[0])) continue;
        this.add('RD004', r.severity, rel, i + 1, `Possible ${r.name} committed to source`);
      }
    });
  }

  checkPatterns(rel, ext, text) {
    const active = this.patterns.filter((r) => r.exts.includes(ext));
    if (!active.length) return;
    lines(text).forEach((l, i) => {
      if (l.includes('riskdebt-ignore')) return;
      for (const r of active) {
        const m = l.match(r.re);
        if (!m || (r.skipPlaceholders && this.isPlaceholder(m[0]))) continue;
        this.add('RD008', r.severity, rel, i + 1, `[${r.framework}] ${r.name}`, r.fix);
      }
    });
  }

  eolFinding(rel, line, product, ver) {
    const date = this.cycles[`${product}:${ver}`];
    if (!date) return;
    const eol = Date.parse(date);
    if (Number.isNaN(eol)) return;
    const days = Math.trunc((eol - this.today) / 86400000);
    if (eol < this.today) this.add('RD005', 'high', rel, line, `${product} ${ver} reached end-of-life on ${date} and no longer receives security fixes`);
    else if (days <= 180) this.add('RD005', 'medium', rel, line, `${product} ${ver} reaches end-of-life on ${date} (in ${days} days)`);
  }

  checkEOL(rel, base, text) {
    const first = text.split('\n')[0].trim();
    let m;
    if ((base === '.nvmrc' || base === '.node-version') && (m = first.match(RE_NODE))) this.eolFinding(rel, 1, 'node', m[1]);
    else if (base === '.python-version' && (m = first.match(RE_MAJMIN))) this.eolFinding(rel, 1, 'python', `${m[1]}.${m[2]}`);
    else if (base === '.php-version' && (m = first.match(RE_MAJMIN))) this.eolFinding(rel, 1, 'php', `${m[1]}.${m[2]}`);
    else if (base === 'runtime.txt' && (m = first.match(RE_PY_RT))) this.eolFinding(rel, 1, 'python', `${m[1]}.${m[2]}`);
    if (base === 'Dockerfile' || base.startsWith('Dockerfile.') || base.endsWith('.dockerfile')) {
      lines(text).forEach((l, i) => {
        const f = l.match(RE_FROM);
        if (!f) return;
        const product = f[1].toLowerCase();
        if (product === 'node') this.eolFinding(rel, i + 1, product, f[2]);
        else if (f[3] !== undefined) this.eolFinding(rel, i + 1, product, `${f[2]}.${f[3]}`);
      });
    }
  }

  checkClaudeSettings(rel, text) {
    const s = asObj(parseJSON(text));
    const perm = asObj(s.permissions);
    if (Array.isArray(perm.allow)) {
      for (const a of perm.allow) {
        if (a === '*' || a === 'Bash' || a === 'Bash(*)') {
          this.add('RD006', 'high', rel, findLine(text, `"${a}"`), `Agent is allowed to run "${a}" without approval (unrestricted shell access)`,
            'Allow only specific commands, e.g. "Bash(npm test)", and keep prompts for anything that writes, deletes or reaches the network.');
        }
      }
    }
    if (perm.defaultMode === 'bypassPermissions') {
      this.add('RD006', 'high', rel, findLine(text, '"bypassPermissions"'), 'Agent permission mode is bypassPermissions, so every action runs without human approval',
        'Use the default or acceptEdits mode and reserve bypass for disposable sandboxes without credentials.');
    }
  }

  checkMCP(rel, text) {
    const s = asObj(parseJSON(text));
    const servers = s.mcpServers ? asObj(s.mcpServers) : asObj(s.servers);
    for (const name of Object.keys(servers).sort()) {
      const srv = asObj(servers[name]);
      const cmd = typeof srv.command === 'string' ? srv.command : '';
      const args = Array.isArray(srv.args) ? srv.args : [];
      if (['npx', 'uvx', 'bunx'].includes(cmd)) {
        for (const arg of args) {
          if (typeof arg !== 'string' || arg === '' || arg.startsWith('-')) continue;
          let pinned = arg.lastIndexOf('@') > 0;
          if (cmd === 'uvx') pinned = pinned || arg.includes('==');
          if (!pinned) {
            this.add('RD006', 'medium', rel, findLine(text, `"${arg}"`),
              `MCP server "${name}" runs ${cmd} ${arg} with no version pin, so a compromised release executes with your agent's access`,
              'Pin the version (e.g. "pkg@1.2.3") and review updates before bumping.');
          }
          break;
        }
      }
      const env = asObj(srv.env);
      for (const k of Object.keys(env).sort()) {
        const v = typeof env[k] === 'string' ? env[k] : '';
        const uk = k.toUpperCase();
        if (v === '' || v.startsWith('$')) continue;
        if (['TOKEN', 'KEY', 'SECRET', 'PASSWORD'].some((w) => uk.includes(w))) {
          this.add('RD006', 'high', rel, findLine(text, `"${k}"`), `MCP server "${name}" has a literal credential in ${k}`,
            `Reference it as "\${${k}}" and keep the value in your shell or secret manager, never in a committed file.`);
        }
      }
    }
  }

  checkWorkflow(rel, text) {
    lines(text).forEach((l, i) => {
      const m = l.match(RE_USES);
      if (!m || m[1].startsWith('./') || m[1].startsWith('docker://')) return;
      const k = m[1].lastIndexOf('@');
      const ref = k >= 0 ? m[1].slice(k + 1) : '';
      if (!RE_SHA.test(ref)) this.add('RD007', 'medium', rel, i + 1, `Action ${m[1]} is not pinned to a commit SHA (ref "${ref}" can be moved by its owner)`);
    });
  }
}

function walk(root, dir, out) {
  const entries = fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const d of entries) {
    const abs = path.join(dir, d.name);
    if (d.isDirectory()) {
      if (!SKIP_DIRS.has(d.name)) walk(root, abs, out);
    } else if (d.isFile()) {
      out.push({ rel: path.relative(root, abs).split(path.sep).join('/'), abs });
    }
  }
}

export function scan(root, opts = {}) {
  let today = opts.today;
  if (!today) {
    const n = new Date();
    today = Date.UTC(n.getUTCFullYear(), n.getUTCMonth(), n.getUTCDate());
  }
  const e = new Engine({ ...opts, today });
  const list = [];
  walk(root, root, list);
  for (const f of list) e.files.add(f.rel);
  let scanned = 0;
  for (const f of list) {
    const base = path.posix.basename(f.rel);
    let ext = extOf(base);
    if (base === 'Dockerfile' || base.startsWith('Dockerfile.')) ext = '.dockerfile';
    if (BINARY_EXTS.has(ext)) continue;
    let buf;
    try {
      if (fs.statSync(f.abs).size > MAX_FILE_SIZE) continue;
      buf = fs.readFileSync(f.abs);
    } catch {
      continue;
    }
    if (buf.subarray(0, 8000).includes(0)) continue;
    const text = buf.toString('utf8');
    scanned++;
    if (base === 'package.json') e.checkPackageJSON(f.rel, text);
    else if (base === 'package-lock.json') e.checkPackageLock(f.rel, text);
    else if (base.startsWith('requirements') && ext === '.txt') e.checkRequirements(f.rel, text);
    else if (ext === '.csproj') e.checkCsproj(f.rel, text);
    e.checkSecrets(f.rel, text);
    e.checkPatterns(f.rel, ext, text);
    e.checkEOL(f.rel, base, text);
    if (endsWithPath(f.rel, '.claude/settings.json') || endsWithPath(f.rel, '.claude/settings.local.json')) e.checkClaudeSettings(f.rel, text);
    if (base === '.mcp.json' || endsWithPath(f.rel, '.cursor/mcp.json') || endsWithPath(f.rel, '.vscode/mcp.json')) e.checkMCP(f.rel, text);
    if (('/' + f.rel).includes('/.github/workflows/') && (ext === '.yml' || ext === '.yaml')) e.checkWorkflow(f.rel, text);
  }
  const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  e.findings.sort((a, b) => cmp(a.file, b.file) || a.line - b.line || cmp(a.rule, b.rule) || cmp(a.message, b.message));
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of e.findings) summary[f.severity]++;
  return { tool: 'riskdebt', version: VERSION, root, scanned, findings: e.findings, summary };
}
