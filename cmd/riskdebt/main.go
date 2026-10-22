package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/oriebalzyuot96/riskdebt/internal/scanner"
)

const usage = `riskdebt - find the security debt hiding in your project

Usage: riskdebt [path] [options]

Options:
  -f, --format <text|json>   output format (default text)
      --fail-on <severity>   exit 1 at or above: critical|high|medium|low|none (default high)
      --today <YYYY-MM-DD>   override today's date (for reproducible EOL checks)
      --blocklist <file>     extra compromised-package list (JSON)
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
	if format != "text" && format != "json" {
		die("--format must be text or json")
	}
	if failOn != "none" && scanner.Rank(failOn) < 0 {
		die("--fail-on must be critical|high|medium|low|none")
	}
	res, err := scanner.Scan(root, opts)
	if err != nil {
		die(err.Error())
	}
	if format == "json" {
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
	fmt.Printf("riskdebt %s - scanned %d files in %s\n\n", r.Version, r.Scanned, r.Root)
	for _, f := range r.Findings {
		fmt.Printf("%s %s  %s:%d\n", paint(colors[f.Severity], fmt.Sprintf("%-8s", upper(f.Severity))), f.Rule, f.File, f.Line)
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
