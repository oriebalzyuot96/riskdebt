package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/oriebalzyuot96/riskdebt/internal/scanner"
)

const usage = `riskdebt - find the security debt hiding in your project

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
`

func die(msg string) {
	fmt.Fprintln(os.Stderr, "riskdebt: "+msg)
	os.Exit(2)
}

func main() {
	root, format, failOn := ".", "text", "high"
	opts := scanner.Options{}
	var since, baselinePath, writeBaseline string
	noBaseline := false
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() string {
			if i+1 >= len(args) {
				die("missing value for " + a)
			}
			i++
			return args[i]
		}
		switch a {
		case "-h", "--help":
			fmt.Print(usage)
			return
		case "-v", "--version":
			fmt.Println(scanner.Version)
			return
		case "-f", "--format":
			format = next()
		case "--fail-on":
			failOn = next()
		case "--today":
			t, err := time.Parse("2006-01-02", next())
			if err != nil {
				die("--today must be YYYY-MM-DD")
			}
			opts.Today = t
		case "--exclude":
			opts.Exclude = append(opts.Exclude, next())
		case "--no-gitignore":
			opts.NoGitignore = true
		case "--max-size":
			kb, err := strconv.Atoi(next())
			if err != nil || kb <= 0 {
				die("--max-size must be a positive number of KB")
			}
			opts.MaxSizeKB = kb
		case "--since":
			since = next()
		case "--baseline":
			baselinePath = next()
		case "--write-baseline":
			writeBaseline = next()
		case "--no-baseline":
			noBaseline = true
		case "--blocklist":
			data, err := os.ReadFile(next())
			if err != nil {
				die(err.Error())
			}
			if err := json.Unmarshal(data, &opts.ExtraBlocklist); err != nil {
				die("bad blocklist: " + err.Error())
			}
		default:
			if len(a) > 0 && a[0] == '-' {
				die("unknown option " + a)
			}
			root = a
		}
	}
	if format != "text" && format != "json" && format != "sarif" {
		die("--format must be text, json or sarif")
	}
	if failOn != "none" && scanner.Rank(failOn) < 0 {
		die("--fail-on must be critical|high|medium|low|none")
	}
	if writeBaseline != "" && (since != "" || baselinePath != "") {
		die("--write-baseline records the full scan; do not combine it with --since or --baseline")
	}
	res, err := scanner.Scan(root, opts)
	if err != nil {
		die(err.Error())
	}

	if writeBaseline != "" {
		data, _ := json.MarshalIndent(scanner.NewBaseline(res), "", "  ")
		if err := os.WriteFile(writeBaseline, append(data, '\n'), 0o644); err != nil {
			die(err.Error())
		}
		fmt.Printf("Baseline written: %d findings -> %s\n", len(res.Findings), writeBaseline)
		return
	}
	if !noBaseline {
		path := baselinePath
		if path == "" {
			if def := filepath.Join(root, scanner.DefaultBaselineFile); fileExists(def) {
				path = def
			}
		}
		if path != "" {
			b, err := scanner.LoadBaseline(path)
			if err != nil {
				die(err.Error())
			}
			res.ApplyBaseline(b)
		}
	}
	if since != "" {
		if err := res.FilterSince(root, since); err != nil {
			die(err.Error())
		}
	}

	if format == "sarif" {
		out, _ := json.MarshalIndent(scanner.SARIF(res), "", "  ")
		fmt.Println(string(out))
	} else if format == "json" {
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
	} else {
		printText(res)
	}
	if failOn != "none" {
		for _, f := range res.Findings {
			if scanner.Rank(f.Severity) >= scanner.Rank(failOn) {
				os.Exit(1)
			}
		}
	}
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func printText(r *scanner.Result) {
	st, _ := os.Stdout.Stat()
	color := st != nil && st.Mode()&os.ModeCharDevice != 0 && os.Getenv("NO_COLOR") == ""
	paint := func(code, s string) string {
		if !color {
			return s
		}
		return "\x1b[" + code + "m" + s + "\x1b[0m"
	}
	colors := map[string]string{"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "2"}
	fmt.Printf("riskdebt %s - scanned %d files in %s (skipped %d folders, %d files: ignored, binary or too large)\n", r.Version, r.Scanned, r.Root, r.Skipped.Dirs, r.Skipped.Files)
	if r.Since != "" {
		fmt.Printf("diff-only: findings on lines changed since %s\n", r.Since)
	}
	if r.Baselined > 0 || r.BaselineStale > 0 {
		fmt.Printf("baseline: %d known findings hidden", r.Baselined)
		if r.BaselineStale > 0 {
			fmt.Printf(", %d entries no longer match (refresh with --write-baseline)", r.BaselineStale)
		}
		fmt.Println()
	}
	fmt.Println()
	for _, f := range r.Findings {
		tags := append(append([]string{}, f.CWE...), f.OWASP...)
		tagText := ""
		if len(tags) > 0 {
			tagText = "  [" + strings.Join(tags, " · ") + "]"
		}
		fmt.Printf("%s %s  %s:%d%s\n", paint(colors[f.Severity], fmt.Sprintf("%-8s", upper(f.Severity))), f.Rule, f.File, f.Line, tagText)
		fmt.Printf("  problem: %s\n", f.Message)
		fmt.Printf("  fix:     %s\n\n", f.Fix)
	}
	s := r.Summary
	fmt.Printf("%d findings: %d critical, %d high, %d medium, %d low\n", len(r.Findings), s["critical"], s["high"], s["medium"], s["low"])
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
