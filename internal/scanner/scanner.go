// Package scanner implements the riskdebt checks. Behaviour must stay identical
// to the Node.js and Python ports; scripts/conformance.mjs enforces that.
package scanner

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oriebalzyuot96/riskdebt/rules"
)

// disableHints is set by tests to prove the hints are only an optimisation: they must never hide a finding.
var disableHints bool

const Version = "0.1.1"

var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// Rank returns the numeric rank of a severity (unknown severities rank -1).
func Rank(s string) int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return -1
}

type Finding struct {
	Rule     string `json:"rule"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
	Fix      string `json:"fix"`
}

type Result struct {
	Tool     string         `json:"tool"`
	Version  string         `json:"version"`
	Root     string         `json:"root"`
	Scanned  int            `json:"scanned"`
	Skipped  Skipped        `json:"skipped"`
	Findings []Finding      `json:"findings"`
	Summary  map[string]int `json:"summary"`
}

// Skipped counts what the walk deliberately did not read, so a clean result is never mistaken for full coverage.
type Skipped struct {
	Dirs  int `json:"dirs"`
	Files int `json:"files"`
}

type CompromisedEntry struct {
	Ecosystem string   `json:"ecosystem"`
	Name      string   `json:"name"`
	Versions  []string `json:"versions"`
	Reason    string   `json:"reason"`
}

type Options struct {
	Today          time.Time
	ExtraBlocklist []CompromisedEntry
	NoGitignore    bool     // do not read the root .gitignore
	MaxSizeKB      int      // skip files larger than this (default 1024)
	Exclude        []string // extra .gitignore-style patterns
}

type metaEntry struct {
	Name string `json:"name"`
	Fix  string `json:"fix"`
}

type secretRule struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Pattern          string   `json:"pattern"`
	Flags            string   `json:"flags"`
	Severity         string   `json:"severity"`
	SkipPlaceholders bool     `json:"skipPlaceholders"`
	Hints            []string `json:"hints"`
	ValueFilter      string   `json:"valueFilter"` // "wordy": skip values that read like words, not like random secrets
	re               *regexp.Regexp
}

type patternRule struct {
	ID               string   `json:"id"`
	Framework        string   `json:"framework"`
	Name             string   `json:"name"`
	Pattern          string   `json:"pattern"`
	Flags            string   `json:"flags"`
	Exts             []string `json:"exts"`
	Severity         string   `json:"severity"`
	SkipPlaceholders bool     `json:"skipPlaceholders"`
	Fix              string   `json:"fix"`
	Hints            []string `json:"hints"`
	re               *regexp.Regexp
}

type engine struct {
	meta         map[string]metaEntry
	placeholders []string
	secrets      []secretRule
	patterns     []patternRule
	cycles       map[string]string
	blocklist    []CompromisedEntry
	today        time.Time
	files        map[string]bool
	findings     []Finding
	ignores      []scopedIgnore
	gitignore    bool // read .gitignore files (the root one and the ones in sub-folders)
	maxSize      int64
	skipped      Skipped
	mu           sync.Mutex // guards findings and skipped while files are scanned in parallel
}

func compile(p, flags string) *regexp.Regexp {
	if strings.Contains(flags, "i") {
		p = "(?i)" + p
	}
	return regexp.MustCompile(p)
}

func newEngine(opts Options) (*engine, error) {
	e := &engine{files: map[string]bool{}, today: opts.Today}
	if err := json.Unmarshal(rules.Meta, &e.meta); err != nil {
		return nil, err
	}
	var sf struct {
		Placeholders []string     `json:"placeholders"`
		Patterns     []secretRule `json:"patterns"`
	}
	if err := json.Unmarshal(rules.Secrets, &sf); err != nil {
		return nil, err
	}
	e.placeholders = sf.Placeholders
	e.secrets = sf.Patterns
	if disableHints {
		for i := range e.secrets {
			e.secrets[i].Hints = nil
		}
	}
	for i := range e.secrets {
		e.secrets[i].re = compile(e.secrets[i].Pattern, e.secrets[i].Flags)
	}
	if err := json.Unmarshal(rules.Patterns, &e.patterns); err != nil {
		return nil, err
	}
	for i := range e.patterns {
		if disableHints {
			e.patterns[i].Hints = nil
		}
		e.patterns[i].re = compile(e.patterns[i].Pattern, e.patterns[i].Flags)
	}
	var ef struct {
		Cycles map[string]string `json:"cycles"`
	}
	if err := json.Unmarshal(rules.EOL, &ef); err != nil {
		return nil, err
	}
	e.cycles = ef.Cycles
	if err := json.Unmarshal(rules.Compromised, &e.blocklist); err != nil {
		return nil, err
	}
	e.blocklist = append(e.blocklist, opts.ExtraBlocklist...)
	return e, nil
}

func (e *engine) skip() {
	e.mu.Lock()
	e.skipped.Files++
	e.mu.Unlock()
}

func (e *engine) add(rule, severity, file string, line int, message, fix string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if fix == "" {
		fix = e.meta[rule].Fix
	}
	e.findings = append(e.findings, Finding{
		Rule: rule, Name: e.meta[rule].Name, Severity: severity,
		File: file, Line: line, Message: message, Fix: fix,
	})
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true,
	"__pycache__": true, ".venv": true, "venv": true, "target": true, "bin": true, "obj": true,
	".next": true, ".nuxt": true, ".angular": true, ".svelte-kit": true, ".turbo": true, ".cache": true,
	"coverage": true, ".gradle": true, ".idea": true, ".vs": true, ".terraform": true, ".tox": true,
	".mypy_cache": true, ".pytest_cache": true, ".parcel-cache": true, "bower_components": true, "out": true,
}

var binaryExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".ico": true, ".pdf": true,
	".zip": true, ".gz": true, ".tar": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".mp4": true, ".mp3": true, ".exe": true, ".dll": true, ".so": true, ".wasm": true,
	// machine-learning models and datasets (often gigabytes)
	".onnx": true, ".gguf": true, ".ggml": true, ".safetensors": true, ".pt": true, ".pth": true, ".ckpt": true,
	".h5": true, ".hdf5": true, ".pb": true, ".tflite": true, ".npy": true, ".npz": true, ".pkl": true,
	".pickle": true, ".joblib": true, ".bin": true, ".model": true, ".weights": true, ".parquet": true, ".feather": true,
	// databases, media, archives, compiled output
	".db": true, ".sqlite": true, ".sqlite3": true, ".mdb": true, ".mov": true, ".avi": true, ".mkv": true,
	".webm": true, ".wav": true, ".flac": true, ".ogg": true, ".bmp": true, ".tiff": true, ".psd": true,
	".otf": true, ".7z": true, ".rar": true, ".jar": true, ".class": true, ".pyc": true, ".iso": true, ".dmg": true,
}

// maxLineLen skips minified one-line bundles: no human wrote them and the regexes are slow on them.
const maxLineLen = 4000

const defaultMaxSizeKB = 1024

func extOf(base string) string {
	i := strings.LastIndex(base, ".")
	if i < 0 {
		return ""
	}
	return strings.ToLower(base[i:])
}

func findLine(text, needle string) int {
	for i, l := range strings.Split(text, "\n") {
		if strings.Contains(l, needle) {
			return i + 1
		}
	}
	return 1
}

// findKeyLine finds the first line containing `"key"` followed by a colon.
func findKeyLine(text, key string) int {
	q := `"` + key + `"`
	for i, l := range strings.Split(text, "\n") {
		if idx := strings.Index(l, q); idx >= 0 {
			if strings.HasPrefix(strings.TrimLeft(l[idx+len(q):], " \t"), ":") {
				return i + 1
			}
		}
	}
	return 1
}

func endsWithPath(rel, p string) bool {
	return rel == p || strings.HasSuffix(rel, "/"+p)
}

func normalizeName(eco, name string) string {
	name = strings.ToLower(name)
	if eco == "pypi" {
		name = strings.NewReplacer("_", "-", ".", "-").Replace(name)
	}
	return name
}

func stripVer(spec string) string { return strings.TrimLeft(spec, "^~=<>v ") }

func (e *engine) checkCompromised(eco, name, version, file string, line int) {
	n := normalizeName(eco, name)
	for _, b := range e.blocklist {
		if b.Ecosystem != eco || normalizeName(eco, b.Name) != n {
			continue
		}
		for _, v := range b.Versions {
			if v == version {
				e.add("RD003", "critical", file, line,
					fmt.Sprintf("%s@%s is a known-compromised release: %s", name, version, b.Reason), "")
				return
			}
		}
	}
}

func classifyNpmSpec(spec string) string {
	for _, p := range []string{"workspace:", "file:", "link:", "npm:"} {
		if strings.HasPrefix(spec, p) {
			return ""
		}
	}
	if spec == "latest" || spec == "*" || spec == "" || spec == "x" {
		return "high"
	}
	for _, p := range []string{"git+", "git:", "http:", "https:", "github:"} {
		if strings.HasPrefix(spec, p) {
			return "high"
		}
	}
	if strings.ContainsAny(spec[:1], "^~><") || strings.Contains(spec, "*") ||
		strings.HasSuffix(spec, ".x") || strings.Contains(spec, "||") || strings.Contains(spec, " - ") {
		return "medium"
	}
	return ""
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func (e *engine) checkPackageJSON(rel, text string) {
	var pj map[string]any
	if json.Unmarshal([]byte(text), &pj) != nil {
		return
	}
	count := 0
	for _, sec := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
		m, ok := pj[sec].(map[string]any)
		if !ok {
			continue
		}
		for _, name := range sortedKeys(m) {
			spec, ok := m[name].(string)
			if !ok {
				continue
			}
			count++
			line := findKeyLine(text, name)
			switch classifyNpmSpec(spec) {
			case "high":
				e.add("RD001", "high", rel, line,
					fmt.Sprintf("%q uses %q, which can resolve to unreviewed or attacker-controlled code", name, spec), "")
			case "medium":
				e.add("RD001", "medium", rel, line,
					fmt.Sprintf("%q uses the range %q; a hijacked release would be pulled in automatically", name, spec), "")
			}
			e.checkCompromised("npm", name, stripVer(spec), rel, line)
		}
	}
	if count > 0 {
		dir := path.Dir(rel)
		has := false
		for _, lf := range []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock"} {
			if e.files[path.Join(dir, lf)] {
				has = true
			}
		}
		if !has {
			e.add("RD002", "medium", rel, 1, "package.json has dependencies but no lockfile is committed", "")
		}
	}
}

func (e *engine) checkPackageLock(rel, text string) {
	var pl struct {
		Packages map[string]map[string]any `json:"packages"`
	}
	if json.Unmarshal([]byte(text), &pl) != nil {
		return
	}
	keys := make([]string, 0, len(pl.Packages))
	for k := range pl.Packages {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == "" {
			continue
		}
		name := k
		if i := strings.LastIndex(k, "node_modules/"); i >= 0 {
			name = k[i+len("node_modules/"):]
		}
		if v, ok := pl.Packages[k]["version"].(string); ok {
			e.checkCompromised("npm", name, v, rel, findLine(text, `"`+k+`"`))
		}
	}
}

var reqName = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)`)

func (e *engine) checkRequirements(rel, text string) {
	hasDep := false
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimRight(strings.TrimSpace(raw), `\`))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") ||
			strings.HasPrefix(line, "git+") || strings.HasPrefix(line, "http") || strings.Contains(line, " @ ") {
			continue
		}
		if k := strings.Index(line, " #"); k >= 0 {
			line = strings.TrimSpace(line[:k])
		}
		if k := strings.Index(line, ";"); k >= 0 {
			line = strings.TrimSpace(line[:k])
		}
		m := reqName.FindString(line)
		if m == "" {
			continue
		}
		hasDep = true
		if k := strings.Index(line, "=="); k >= 0 {
			ver := strings.TrimLeft(strings.TrimSpace(line[k+2:]), "=")
			e.checkCompromised("pypi", m, strings.TrimSpace(ver), rel, i+1)
		} else {
			e.add("RD001", "medium", rel, i+1,
				fmt.Sprintf("%q is not pinned with ==; installs can silently change", m), "")
		}
	}
	if hasDep && !strings.Contains(text, "--hash=") {
		e.add("RD002", "low", rel, 1, "requirements file has no --hash entries, so artifacts are not verified", "")
	}
}

var nugetRef = regexp.MustCompile(`<PackageReference\s+Include="([^"]+)"[^>]*?\sVersion="([^"]*)"`)

func (e *engine) checkCsproj(rel, text string) {
	for i, l := range strings.Split(text, "\n") {
		m := nugetRef.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if strings.Contains(m[2], "*") || strings.Contains(m[2], ",") {
			e.add("RD001", "medium", rel, i+1,
				fmt.Sprintf("NuGet package %q uses the floating version %q", m[1], m[2]),
				"Pin an exact version, enable lock files (<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>) and restore with --locked-mode.")
		}
	}
}

// hasHint reports whether a rule can possibly match a file: lower is the lower-cased file text.
func hasHint(lower string, hints []string) bool {
	if len(hints) == 0 {
		return true
	}
	for _, h := range hints {
		if strings.Contains(lower, h) {
			return true
		}
	}
	return false
}

func (e *engine) checkSecrets(rel, text, lower string) {
	var active []*secretRule
	for i := range e.secrets {
		if hasHint(lower, e.secrets[i].Hints) {
			active = append(active, &e.secrets[i])
		}
	}
	if len(active) == 0 {
		return
	}
	lowerLines := strings.Split(lower, "\n")
	for i, l := range strings.Split(text, "\n") {
		if len(l) > maxLineLen || strings.Contains(l, "riskdebt-ignore") {
			continue
		}
		for _, r := range active {
			if i < len(lowerLines) && !hasHint(lowerLines[i], r.Hints) {
				continue
			}
			m := r.re.FindString(l)
			if m == "" {
				continue
			}
			if r.SkipPlaceholders && e.isPlaceholder(m) {
				continue
			}
			if r.ValueFilter == "wordy" && isWordy(lastQuoted(m)) {
				continue
			}
			e.add("RD004", r.Severity, rel, i+1, "Possible "+r.Name+" committed to source", "")
		}
	}
}

// lastQuoted returns the text inside the last quoted string of a match such as token: "abc".
func lastQuoted(m string) string {
	if len(m) < 2 {
		return m
	}
	q := m[len(m)-1]
	if q != '"' && q != '\'' {
		return m
	}
	if i := strings.LastIndexByte(m[:len(m)-1], q); i >= 0 {
		return m[i+1 : len(m)-1]
	}
	return m
}

// isWordy reports whether a value reads like words (a route, an error code, a CSS variable) rather than a random
// secret: at least two words (split on _ - / + and camelCase), each three or more letters, and at most two digits.
func isWordy(v string) bool {
	digits := 0
	var tokens []string
	var cur []byte
	flush := func() {
		if len(cur) > 0 {
			tokens = append(tokens, string(cur))
			cur = cur[:0]
		}
	}
	var prev byte
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
			cur = append(cur, c)
		case c == '_' || c == '-' || c == '/' || c == '+':
			flush()
		case c >= 'A' && c <= 'Z' && prev >= 'a' && prev <= 'z':
			flush()
			cur = append(cur, c)
		default:
			cur = append(cur, c)
		}
		prev = c
	}
	flush()
	if digits > 2 || len(tokens) < 2 {
		return false
	}
	for _, t := range tokens {
		if len(t) < 3 {
			return false
		}
	}
	return true
}

func (e *engine) isPlaceholder(m string) bool {
	lm := strings.ToLower(m)
	for _, p := range e.placeholders {
		if strings.Contains(lm, p) {
			return true
		}
	}
	return false
}

func (e *engine) checkPatterns(rel, ext, text, lower string) {
	var active []*patternRule
	for i := range e.patterns {
		r := &e.patterns[i]
		for _, x := range r.Exts {
			if x == ext && hasHint(lower, r.Hints) {
				active = append(active, r)
				break
			}
		}
	}
	if len(active) == 0 {
		return
	}
	lowerLines := strings.Split(lower, "\n")
	for i, l := range strings.Split(text, "\n") {
		if len(l) > maxLineLen || strings.Contains(l, "riskdebt-ignore") {
			continue
		}
		for _, r := range active {
			if i < len(lowerLines) && !hasHint(lowerLines[i], r.Hints) {
				continue
			}
			m := r.re.FindString(l)
			if m == "" || (r.SkipPlaceholders && e.isPlaceholder(m)) {
				continue
			}
			e.add("RD008", r.Severity, rel, i+1, fmt.Sprintf("[%s] %s", r.Framework, r.Name), r.Fix)
		}
	}
}

var (
	reNode   = regexp.MustCompile(`^v?(\d+)`)
	reMajMin = regexp.MustCompile(`^(\d+)\.(\d+)`)
	rePyRT   = regexp.MustCompile(`python-(\d+)\.(\d+)`)
	reFrom   = regexp.MustCompile(`(?i)^\s*FROM\s+(?:--\S+\s+)*(node|php|python):v?(\d+)(?:\.(\d+))?`)
)

func (e *engine) eolFinding(rel string, line int, product, ver string) {
	date, ok := e.cycles[product+":"+ver]
	if !ok {
		return
	}
	eol, err := time.Parse("2006-01-02", date)
	if err != nil {
		return
	}
	days := int(eol.Sub(e.today).Hours() / 24)
	if eol.Before(e.today) {
		e.add("RD005", "high", rel, line, fmt.Sprintf("%s %s reached end-of-life on %s and no longer receives security fixes", product, ver, date), "")
	} else if days <= 180 {
		e.add("RD005", "medium", rel, line, fmt.Sprintf("%s %s reaches end-of-life on %s (in %d days)", product, ver, date, days), "")
	}
}

func (e *engine) checkEOL(rel, base, text string) {
	first := strings.TrimSpace(strings.SplitN(text, "\n", 2)[0])
	switch base {
	case ".nvmrc", ".node-version":
		if m := reNode.FindStringSubmatch(first); m != nil {
			e.eolFinding(rel, 1, "node", m[1])
		}
	case ".python-version":
		if m := reMajMin.FindStringSubmatch(first); m != nil {
			e.eolFinding(rel, 1, "python", m[1]+"."+m[2])
		}
	case ".php-version":
		if m := reMajMin.FindStringSubmatch(first); m != nil {
			e.eolFinding(rel, 1, "php", m[1]+"."+m[2])
		}
	case "runtime.txt":
		if m := rePyRT.FindStringSubmatch(first); m != nil {
			e.eolFinding(rel, 1, "python", m[1]+"."+m[2])
		}
	}
	if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") || strings.HasSuffix(base, ".dockerfile") {
		for i, l := range strings.Split(text, "\n") {
			m := reFrom.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			product := strings.ToLower(m[1])
			if product == "node" {
				e.eolFinding(rel, i+1, product, m[2])
			} else if m[3] != "" {
				e.eolFinding(rel, i+1, product, m[2]+"."+m[3])
			}
		}
	}
}

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

func (e *engine) checkClaudeSettings(rel, text string) {
	var s map[string]any
	if json.Unmarshal([]byte(text), &s) != nil {
		return
	}
	perm := asMap(s["permissions"])
	if allow, ok := perm["allow"].([]any); ok {
		for _, a := range allow {
			if str, ok := a.(string); ok && (str == "*" || str == "Bash" || str == "Bash(*)") {
				e.add("RD006", "high", rel, findLine(text, `"`+str+`"`),
					fmt.Sprintf("Agent is allowed to run %q without approval (unrestricted shell access)", str),
					"Allow only specific commands, e.g. \"Bash(npm test)\", and keep prompts for anything that writes, deletes or reaches the network.")
			}
		}
	}
	if perm["defaultMode"] == "bypassPermissions" {
		e.add("RD006", "high", rel, findLine(text, `"bypassPermissions"`),
			"Agent permission mode is bypassPermissions, so every action runs without human approval",
			"Use the default or acceptEdits mode and reserve bypass for disposable sandboxes without credentials.")
	}
}

func (e *engine) checkMCP(rel, text string) {
	var s map[string]any
	if json.Unmarshal([]byte(text), &s) != nil {
		return
	}
	servers := asMap(s["mcpServers"])
	if servers == nil {
		servers = asMap(s["servers"])
	}
	for _, name := range sortedKeys(servers) {
		srv := asMap(servers[name])
		cmd, _ := srv["command"].(string)
		args, _ := srv["args"].([]any)
		if cmd == "npx" || cmd == "uvx" || cmd == "bunx" {
			for _, a := range args {
				arg, _ := a.(string)
				if arg == "" || strings.HasPrefix(arg, "-") {
					continue
				}
				pinned := strings.LastIndex(arg, "@") > 0
				if cmd == "uvx" {
					pinned = pinned || strings.Contains(arg, "==")
				}
				if !pinned {
					e.add("RD006", "medium", rel, findLine(text, `"`+arg+`"`),
						fmt.Sprintf("MCP server %q runs %s %s with no version pin, so a compromised release executes with your agent's access", name, cmd, arg),
						"Pin the version (e.g. \"pkg@1.2.3\") and review updates before bumping.")
				}
				break
			}
		}
		env := asMap(srv["env"])
		for _, k := range sortedKeys(env) {
			v, _ := env[k].(string)
			uk := strings.ToUpper(k)
			if v == "" || strings.HasPrefix(v, "$") {
				continue
			}
			if strings.Contains(uk, "TOKEN") || strings.Contains(uk, "KEY") || strings.Contains(uk, "SECRET") || strings.Contains(uk, "PASSWORD") {
				e.add("RD006", "high", rel, findLine(text, `"`+k+`"`),
					fmt.Sprintf("MCP server %q has a literal credential in %s", name, k),
					"Reference it as \"${"+k+"}\" and keep the value in your shell or secret manager, never in a committed file.")
			}
		}
	}
}

var reUses = regexp.MustCompile(`^\s*-?\s*uses:\s*['"]?([^\s'"#]+)`)
var reSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

func (e *engine) checkWorkflow(rel, text string) {
	for i, l := range strings.Split(text, "\n") {
		m := reUses.FindStringSubmatch(l)
		if m == nil || strings.HasPrefix(m[1], "./") || strings.HasPrefix(m[1], "docker://") {
			continue
		}
		ref := ""
		if k := strings.LastIndex(m[1], "@"); k >= 0 {
			ref = m[1][k+1:]
		}
		if !reSHA.MatchString(ref) {
			e.add("RD007", "medium", rel, i+1,
				fmt.Sprintf("Action %s is not pinned to a commit SHA (ref %q can be moved by its owner)", m[1], ref), "")
		}
	}
}

// scopedIgnore is an ignore rule that only applies below scope (a folder relative to the scan root; "" = everywhere).
type scopedIgnore struct {
	rule  ignoreRule
	scope string
}

func (e *engine) addIgnores(scope string, rules ...ignoreRule) {
	for _, r := range rules {
		e.ignores = append(e.ignores, scopedIgnore{rule: r, scope: scope})
	}
}

// loadNestedGitignore reads dir/.gitignore (dir is relative to the scan root) the way git does: its patterns only
// apply inside dir, and "/pattern" is anchored to dir.
func (e *engine) loadNestedGitignore(dirAbs, dirRel string) {
	if !e.gitignore {
		return
	}
	if data, err := os.ReadFile(filepath.Join(dirAbs, ".gitignore")); err == nil {
		e.addIgnores(dirRel, parseIgnoreText(string(data))...)
	}
}

func (e *engine) loadIgnores(root string, opts Options) {
	e.gitignore = !opts.NoGitignore
	for _, p := range builtinIgnores {
		if r, ok := parseIgnoreLine(p); ok {
			e.addIgnores("", r)
		}
	}
	files := []string{".riskdebtignore"}
	if !opts.NoGitignore {
		files = append(files, ".gitignore")
	}
	for _, name := range files {
		if data, err := os.ReadFile(filepath.Join(root, name)); err == nil {
			e.addIgnores("", parseIgnoreText(string(data))...)
		}
	}
	for _, p := range opts.Exclude {
		if r, ok := parseIgnoreLine(p); ok {
			e.addIgnores("", r)
		}
	}
	kb := opts.MaxSizeKB
	if kb <= 0 {
		kb = defaultMaxSizeKB
	}
	e.maxSize = int64(kb) * 1024
}

func (e *engine) ignored(rel, base string, isDir bool) bool {
	for _, s := range e.ignores {
		sub := rel
		if s.scope != "" {
			if !strings.HasPrefix(rel, s.scope+"/") {
				continue
			}
			sub = rel[len(s.scope)+1:]
		}
		if s.rule.matches(sub, base, isDir) {
			return true
		}
	}
	return false
}

type entry struct{ rel, abs string }

const scanWorkers = 8

func scanFile(e *engine, rel, abs string, scanned *int64) {
	base := path.Base(rel)
	ext := extOf(base)
	if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") {
		ext = ".dockerfile"
	}
	if binaryExts[ext] {
		e.skip()
		return
	}
	info, err := os.Stat(abs)
	if err != nil || info.Size() > e.maxSize {
		e.skip()
		return
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		e.skip()
		return
	}
	head := data
	if len(head) > 8000 {
		head = head[:8000]
	}
	if strings.IndexByte(string(head), 0) >= 0 {
		e.skip()
		return
	}
	text := string(data)
	atomic.AddInt64(scanned, 1)
	switch {
	case base == "package.json":
		e.checkPackageJSON(rel, text)
	case base == "package-lock.json":
		e.checkPackageLock(rel, text)
	case strings.HasPrefix(base, "requirements") && ext == ".txt":
		e.checkRequirements(rel, text)
	case ext == ".csproj":
		e.checkCsproj(rel, text)
	}
	lower := strings.ToLower(text)
	e.checkSecrets(rel, text, lower)
	e.checkPatterns(rel, ext, text, lower)
	e.checkEOL(rel, base, text)
	if endsWithPath(rel, ".claude/settings.json") || endsWithPath(rel, ".claude/settings.local.json") {
		e.checkClaudeSettings(rel, text)
	}
	if base == ".mcp.json" || endsWithPath(rel, ".cursor/mcp.json") || endsWithPath(rel, ".vscode/mcp.json") {
		e.checkMCP(rel, text)
	}
	if strings.Contains("/"+rel, "/.github/workflows/") && (ext == ".yml" || ext == ".yaml") {
		e.checkWorkflow(rel, text)
	}
}

// Scan walks root and returns all findings.
func Scan(root string, opts Options) (*Result, error) {
	if opts.Today.IsZero() {
		n := time.Now().UTC()
		opts.Today = time.Date(n.Year(), n.Month(), n.Day(), 0, 0, 0, 0, time.UTC)
	}
	e, err := newEngine(opts)
	if err != nil {
		return nil, err
	}
	e.loadIgnores(root, opts)
	var list []entry
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if p != root && (skipDirs[d.Name()] || e.ignored(rel, d.Name(), true)) {
				e.skipped.Dirs++
				return filepath.SkipDir
			}
			if p != root {
				e.loadNestedGitignore(p, rel)
			}
			return nil
		}
		if e.ignored(rel, d.Name(), false) {
			e.skipped.Files++
			return nil
		}
		e.files[rel] = true
		list = append(list, entry{rel, p})
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Files are independent, and reading them is mostly waiting on the disk (and antivirus), so scan them in parallel.
	// Findings are sorted below, so the result does not depend on the order the workers finish in.
	var scanned int64
	jobs := make(chan entry)
	var wg sync.WaitGroup
	for w := 0; w < scanWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range jobs {
				scanFile(e, f.rel, f.abs, &scanned)
			}
		}()
	}
	for _, f := range list {
		jobs <- f
	}
	close(jobs)
	wg.Wait()
	sort.SliceStable(e.findings, func(i, j int) bool {
		a, b := e.findings[i], e.findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Message < b.Message
	})
	summary := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range e.findings {
		summary[f.Severity]++
	}
	if e.findings == nil {
		e.findings = []Finding{}
	}
	return &Result{Tool: "riskdebt", Version: Version, Root: root, Scanned: int(scanned), Skipped: e.skipped, Findings: e.findings, Summary: summary}, nil
}
