"""Fingerprints, baselines and --since filtering. Must behave exactly like internal/scanner/baseline.go and
node/src/baseline.js, so a baseline file written by one implementation works with the others."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

DEFAULT_BASELINE_FILE = ".riskdebt-baseline.json"


def _normalize_ws(s: str) -> str:
    return " ".join(s.split())


def fingerprint_all(findings: list, root: str) -> None:
    """Gives each finding an id built from the rule, the file and the text of the offending line (not its number),
    so a finding keeps its id when lines above it are added or removed. Findings that share all three get an
    occurrence index. findings must already be sorted."""
    by_file: dict[str, list] = {}
    for f in findings:
        by_file.setdefault(f["file"], []).append(f)
    for file, items in by_file.items():
        try:
            lines = (Path(root) / file).read_text(encoding="utf-8", errors="replace").split("\n")
        except OSError:
            lines = []
        seen: dict[str, int] = {}
        for f in items:
            lt = _normalize_ws(lines[f["line"] - 1]) if 1 <= f["line"] <= len(lines) else ""
            base = f"{f['rule']}\x00{file}\x00{lt}"
            n = seen.get(base, 0)
            seen[base] = n + 1
            f["fingerprint"] = hashlib.sha256(f"{base}\x00{n}".encode("utf-8")).hexdigest()[:20]


def new_baseline(result: dict, version: str) -> dict:
    findings = [{"fingerprint": f["fingerprint"], "rule": f["rule"], "file": f["file"], "line": f["line"]}
                for f in result["findings"]]
    findings.sort(key=lambda x: (x["file"], x["line"], x["rule"], x["fingerprint"]))
    return {"version": 1, "tool": "riskdebt", "toolVersion": version, "findings": findings}


def load_baseline(path: str) -> dict:
    try:
        b = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        raise ValueError(f"bad baseline {path}: {err}") from err
    if b.get("version") != 1:
        raise ValueError(f"baseline {path} has unsupported version {b.get('version')}")
    return b


def summarize(findings: list) -> dict:
    s = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s[f["severity"]] += 1
    return s


def apply_baseline(result: dict, baseline: dict) -> None:
    """Hides the findings that are in the baseline and counts baseline entries that match nothing now."""
    known = {e["fingerprint"] for e in baseline["findings"]}
    current = {f["fingerprint"] for f in result["findings"]}
    kept = [f for f in result["findings"] if f["fingerprint"] not in known]
    result["baselined"] += len(result["findings"]) - len(kept)
    result["baselineStale"] += sum(1 for e in baseline["findings"] if e["fingerprint"] not in current)
    result["findings"] = kept
    result["summary"] = summarize(kept)


def _run_git(root: str, args: list) -> str:
    r = subprocess.run(["git", "-C", root, "-c", "core.quotepath=false", *args], capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise ValueError(f"git {args[0]} failed: {r.stderr.strip()}")
    return r.stdout


def _changed_lines(root: str, ref: str) -> dict:
    """Per file (relative to root): the lines added or changed since ref in the working tree. Untracked files count in full."""
    if ref.startswith("-"):
        raise ValueError(f'--since needs a git ref, got "{ref}"')
    diff = _run_git(root, ["diff", "--relative", "-U0", "--no-color", "--no-ext-diff", "--no-renames", ref, "--"])
    changed: dict[str, dict] = {}
    cur = ""
    for raw in diff.split("\n"):
        l = raw.rstrip("\r")
        if l.startswith("+++ "):
            p = l[4:]
            tab = p.find("\t")
            if tab >= 0:
                p = p[:tab]
            if p == "/dev/null":
                cur = ""
            else:
                cur = p[2:] if p.startswith("b/") else p
                changed.setdefault(cur, {"all": False, "ranges": []})
        elif l.startswith("@@") and cur:
            i = l.find(" +")
            if i < 0:
                continue
            rest = l[i + 2:]
            sp = rest.find(" ")
            if sp >= 0:
                rest = rest[:sp]
            a, _, b = rest.partition(",")
            start = int(a)
            count = int(b) if b != "" else 1
            if count > 0:
                changed[cur]["ranges"].append((start, start + count - 1))
    for p in _run_git(root, ["ls-files", "--others", "--exclude-standard"]).split("\n"):
        q = p.rstrip("\r")
        if q:
            changed[q] = {"all": True, "ranges": []}
    return changed


def filter_since(result: dict, root: str, ref: str) -> None:
    """Keeps only findings on lines that changed since the git ref (plus file-level findings, reported on line 1, of
    files that changed at all). This is what a pull request adds."""
    changed = _changed_lines(root, ref)
    kept = []
    for f in result["findings"]:
        c = changed.get(f["file"])
        if c and (f["line"] == 1 or c["all"] or any(a <= f["line"] <= b for a, b in c["ranges"])):
            kept.append(f)
    result["findings"] = kept
    result["summary"] = summarize(kept)
    result["since"] = ref
