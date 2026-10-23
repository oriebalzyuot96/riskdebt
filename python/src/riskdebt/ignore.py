""".gitignore-style matching. Supported: comments, trailing "/" (directories only), a leading or inner "/"
(anchored to the scan root), "*", "**" and "?". Negation ("!") is not supported.
Must behave exactly like internal/scanner/ignore.go and node/src/ignore.js."""
from __future__ import annotations

import re
from typing import NamedTuple

# Generated or minified files that only produce noise and slow the scan down.
BUILTIN_IGNORES = ["*.min.js", "*.min.css", "*.map"]


class Rule(NamedTuple):
    re: re.Pattern[str]
    dir_only: bool
    has_slash: bool


def glob_to_regex(p: str) -> str:
    out = []
    i = 0
    while i < len(p):
        c = p[i]
        if c == "*" and p[i + 1:i + 2] == "*":
            if p[i + 2:i + 3] == "/":
                out.append("(?:.*/)?")
                i += 3
            else:
                out.append(".*")
                i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return "".join(out)


def parse_ignore_line(line: str) -> Rule | None:
    line = line.strip()
    if line == "" or line.startswith(("#", "!")):
        return None
    dir_only = line.endswith("/")
    line = line.rstrip("/")
    anchored = line.startswith("/")
    if anchored:
        line = line[1:]
    if line == "":
        return None
    return Rule(re.compile("^" + glob_to_regex(line) + "$"), dir_only, anchored or "/" in line)


def parse_ignore_text(text: str) -> list[Rule]:
    return [r for r in (parse_ignore_line(l) for l in text.split("\n")) if r]


def matches(rule: Rule, rel: str, base: str, is_dir: bool) -> bool:
    if rule.dir_only and not is_dir:
        return False
    return rule.re.search(rel if rule.has_slash else base) is not None
