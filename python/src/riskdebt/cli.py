from __future__ import annotations

import json
import os
import re
import sys
from datetime import date

from .sarif import to_sarif
from .scanner import VERSION, rank, scan

USAGE = """riskdebt - find the security debt hiding in your project

Usage: riskdebt [path] [options]

Options:
  -f, --format <text|json|sarif>   output format (default text)
      --fail-on <severity>   exit 1 at or above: critical|high|medium|low|none (default high)
      --today <YYYY-MM-DD>   override today's date (for reproducible EOL checks)
      --blocklist <file>     extra compromised-package list (JSON)
  -v, --version              print version
  -h, --help                 show this help
"""


def _die(msg: str) -> None:
    sys.stderr.write(f"riskdebt: {msg}\n")
    sys.exit(2)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    root, fmt, fail_on = ".", "text", "high"
    today = None
    extra = None
    i = 0
    while i < len(argv):
        a = argv[i]

        def nxt() -> str:
            nonlocal i
            if i + 1 >= len(argv):
                _die(f"missing value for {a}")
            i += 1
            return argv[i]

        if a in ("-h", "--help"):
            sys.stdout.write(USAGE)
            return 0
        if a in ("-v", "--version"):
            print(VERSION)
            return 0
        if a in ("-f", "--format"):
            fmt = nxt()
        elif a == "--fail-on":
            fail_on = nxt()
        elif a == "--today":
            v = nxt()
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
                _die("--today must be YYYY-MM-DD")
            today = date.fromisoformat(v)
        elif a == "--blocklist":
            try:
                with open(nxt(), encoding="utf-8") as fh:
                    extra = json.load(fh)
            except (OSError, ValueError) as err:
                _die(f"bad blocklist: {err}")
        elif a.startswith("-"):
            _die(f"unknown option {a}")
        else:
            root = a
        i += 1

    if fmt not in ("text", "json", "sarif"):
        _die("--format must be text, json or sarif")
    if fail_on != "none" and rank(fail_on) < 0:
        _die("--fail-on must be critical|high|medium|low|none")

    res = scan(root, today=today, extra_blocklist=extra)
    if fmt == "sarif":
        print(json.dumps(to_sarif(res), indent=2))
    elif fmt == "json":
        print(json.dumps(res, indent=2))
    else:
        _print_text(res)
    if fail_on != "none" and any(rank(f["severity"]) >= rank(fail_on) for f in res["findings"]):
        return 1
    return 0


def _print_text(r: dict) -> None:
    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    colors = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "2"}

    def paint(code: str, s: str) -> str:
        return f"\x1b[{code}m{s}\x1b[0m" if color else s

    print(f"riskdebt {r['version']} - scanned {r['scanned']} files in {r['root']}\n")
    for f in r["findings"]:
        print(f"{paint(colors[f['severity']], f['severity'].upper().ljust(8))} {f['rule']}  {f['file']}:{f['line']}")
        print(f"  problem: {f['message']}")
        print(f"  fix:     {f['fix']}\n")
    s = r["summary"]
    print(f"{len(r['findings'])} findings: {s['critical']} critical, {s['high']} high, {s['medium']} medium, {s['low']} low")
