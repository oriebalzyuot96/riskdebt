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
	"time"

	"github.com/oriebalzyuot96/riskdebt/rules"
)

const Version = "0.1.0"

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
	Findings []Finding      `json:"findings"`
	Summary  map[string]int `json:"summary"`
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
}

type metaEntry struct {
	Name string `json:"name"`
	Fix  string `json:"fix"`
}

type secretRule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Pattern          string `json:"pattern"`
	Flags            string `json:"flags"`
	Severity         string `json:"severity"`
	SkipPlaceholders bool   `json:"skipPlaceholders"`
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
	for i := range e.secrets {
		e.secrets[i].re = compile(e.secrets[i].Pattern, e.secrets[i].Flags)
	}
	if err := json.Unmarshal(rules.Patterns, &e.patterns); err != nil {
		return nil, err
	}
	for i := range e.patterns {
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

func (e *engine) add(rule, severity, file string, line int, message, fix string) {
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
}

var binaryExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".ico": true, ".pdf": true,
	".zip": true, ".gz": true, ".tar": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".mp4": true, ".mp3": true, ".exe": true, ".dll": true, ".so": true, ".wasm": true,
}

const maxFileSize = 1 << 20

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

func (e *engine) checkSecrets(rel, text string) {
	for i, l := range strings.Split(text, "\n") {
		if strings.Contains(l, "riskdebt-ignore") {
			continue
		}
		for _, r := range e.secrets {
			m := r.re.FindString(l)
			if m == "" {
				continue
			}
			if r.SkipPlaceholders && e.isPlaceholder(m) {
				continue
			}
			e.add("RD004", r.Severity, rel, i+1, "Possible "+r.Name+" committed to source", "")
		}
	}
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

func (e *engine) checkPatterns(rel, ext, text string) {
	for i, l := range strings.Split(text, "\n") {
		if strings.Contains(l, "riskdebt-ignore") {
			continue
		}
		for _, r := range e.patterns {
			ok := false
			for _, x := range r.Exts {
				if x == ext {
					ok = true
				}
			}
			if !ok {
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
	type entry struct{ rel, abs string }
	var list []entry
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		e.files[rel] = true
		list = append(list, entry{rel, p})
		return nil
	})
	if err != nil {
		return nil, err
	}
	scanned := 0
	for _, f := range list {
		base := path.Base(f.rel)
		ext := extOf(base)
		if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") {
			ext = ".dockerfile"
		}
		if binaryExts[ext] {
			continue
		}
		info, err := os.Stat(f.abs)
		if err != nil || info.Size() > maxFileSize {
			continue
		}
		data, err := os.ReadFile(f.abs)
		if err != nil {
			continue
		}
		head := data
		if len(head) > 8000 {
			head = head[:8000]
		}
		if strings.IndexByte(string(head), 0) >= 0 {
			continue
		}
		text := string(data)
		scanned++
		switch {
		case base == "package.json":
			e.checkPackageJSON(f.rel, text)
		case base == "package-lock.json":
			e.checkPackageLock(f.rel, text)
		case strings.HasPrefix(base, "requirements") && ext == ".txt":
			e.checkRequirements(f.rel, text)
		case ext == ".csproj":
			e.checkCsproj(f.rel, text)
		}
		e.checkSecrets(f.rel, text)
		e.checkPatterns(f.rel, ext, text)
		e.checkEOL(f.rel, base, text)
		if endsWithPath(f.rel, ".claude/settings.json") || endsWithPath(f.rel, ".claude/settings.local.json") {
			e.checkClaudeSettings(f.rel, text)
		}
		if base == ".mcp.json" || endsWithPath(f.rel, ".cursor/mcp.json") || endsWithPath(f.rel, ".vscode/mcp.json") {
			e.checkMCP(f.rel, text)
		}
		if strings.Contains("/"+f.rel, "/.github/workflows/") && (ext == ".yml" || ext == ".yaml") {
			e.checkWorkflow(f.rel, text)
		}
	}
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
	return &Result{Tool: "riskdebt", Version: Version, Root: root, Scanned: scanned, Findings: e.findings, Summary: summary}, nil
}
