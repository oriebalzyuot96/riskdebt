package scanner

import (
	"regexp"
	"strings"
)

// ignoreRule is one .gitignore-style line. Supported: comments, trailing "/" (directories only),
// a leading or inner "/" (anchored to the scan root), "*", "**" and "?". Negation ("!") is not supported.
type ignoreRule struct {
	re       *regexp.Regexp
	dirOnly  bool
	hasSlash bool
}

// builtinIgnores are generated or minified files that only produce noise and slow the scan down.
var builtinIgnores = []string{"*.min.js", "*.min.css", "*.map"}

func globToRegex(p string) string {
	rs := []rune(p)
	var b strings.Builder
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == '*' && i+1 < len(rs) && rs[i+1] == '*':
			if i+2 < len(rs) && rs[i+2] == '/' {
				b.WriteString("(?:.*/)?")
				i += 2
			} else {
				b.WriteString(".*")
				i++
			}
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	return b.String()
}

func parseIgnoreLine(line string) (ignoreRule, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
		return ignoreRule{}, false
	}
	dirOnly := strings.HasSuffix(line, "/")
	line = strings.TrimRight(line, "/")
	anchored := strings.HasPrefix(line, "/")
	line = strings.TrimPrefix(line, "/")
	if line == "" {
		return ignoreRule{}, false
	}
	return ignoreRule{
		re:       regexp.MustCompile("^" + globToRegex(line) + "$"),
		dirOnly:  dirOnly,
		hasSlash: anchored || strings.Contains(line, "/"),
	}, true
}

func parseIgnoreText(text string) []ignoreRule {
	var out []ignoreRule
	for _, l := range strings.Split(text, "\n") {
		if r, ok := parseIgnoreLine(l); ok {
			out = append(out, r)
		}
	}
	return out
}

func (r ignoreRule) matches(rel, base string, isDir bool) bool {
	if r.dirOnly && !isDir {
		return false
	}
	if r.hasSlash {
		return r.re.MatchString(rel)
	}
	return r.re.MatchString(base)
}
