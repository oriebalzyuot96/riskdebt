// .gitignore-style matching. Supported: comments, trailing "/" (directories only), a leading or inner "/"
// (anchored to the scan root), "*", "**" and "?". Negation ("!") is not supported.
// Must behave exactly like internal/scanner/ignore.go and python/src/riskdebt/ignore.py.

// Generated or minified files that only produce noise and slow the scan down.
export const BUILTIN_IGNORES = ['*.min.js', '*.min.css', '*.map'];

const escapeChar = (c) => (/[.*+?^${}()|[\]\\]/.test(c) ? '\\' + c : c);

export function globToRegex(p) {
  const cs = [...p];
  let out = '';
  for (let i = 0; i < cs.length; i++) {
    const c = cs[i];
    if (c === '*' && cs[i + 1] === '*') {
      if (cs[i + 2] === '/') {
        out += '(?:.*/)?';
        i += 2;
      } else {
        out += '.*';
        i += 1;
      }
    } else if (c === '*') out += '[^/]*';
    else if (c === '?') out += '[^/]';
    else out += escapeChar(c);
  }
  return out;
}

export function parseIgnoreLine(line) {
  line = line.trim();
  if (line === '' || line.startsWith('#') || line.startsWith('!')) return null;
  const dirOnly = line.endsWith('/');
  line = line.replace(/\/+$/, '');
  const anchored = line.startsWith('/');
  if (anchored) line = line.slice(1);
  if (line === '') return null;
  return { re: new RegExp('^' + globToRegex(line) + '$'), dirOnly, hasSlash: anchored || line.includes('/') };
}

export function parseIgnoreText(text) {
  return text.split('\n').map(parseIgnoreLine).filter(Boolean);
}

export function matches(rule, rel, base, isDir) {
  if (rule.dirOnly && !isDir) return false;
  return rule.re.test(rule.hasSlash ? rel : base);
}
