"""riskdebt scanner (Python). Behaviour must stay identical to the Go and Node.js
ports; scripts/conformance.mjs enforces that against shared fixtures."""
from __future__ import annotations

import json
import os
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "0.1.0"

_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def rank(sev: str) -> int:
    return _RANK.get(sev, -1)


def _rules_dir() -> Path:
    here = Path(__file__).resolve().parent
    candidates = [os.environ.get("RISKDEBT_RULES"), here / "rules", here.parent.parent.parent / "rules"]
    for c in candidates:
        if c and (Path(c) / "meta.json").exists():
            return Path(c)
    raise RuntimeError("riskdebt: cannot find rules directory")


def _load(d: Path, name: str) -> Any:
    return json.loads((d / name).read_text(encoding="utf-8"))


def _compile(p: str, flags: str = "") -> re.Pattern[str]:
    return re.compile(p, re.I if "i" in flags else 0)


SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv", "venv", "target", "bin", "obj"}
BINARY_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar", ".woff", ".woff2",
               ".ttf", ".eot", ".mp4", ".mp3", ".exe", ".dll", ".so", ".wasm"}
MAX_FILE_SIZE = 1 << 20


def _ext(base: str) -> str:
    i = base.rfind(".")
    return "" if i < 0 else base[i:].lower()


def _find_line(text: str, needle: str) -> int:
    for i, l in enumerate(text.split("\n")):
        if needle in l:
            return i + 1
    return 1


def _find_key_line(text: str, key: str) -> int:
    q = f'"{key}"'
    for i, l in enumerate(text.split("\n")):
        idx = l.find(q)
        if idx >= 0 and l[idx + len(q):].lstrip(" \t").startswith(":"):
            return i + 1
    return 1


def _ends_with_path(rel: str, p: str) -> bool:
    return rel == p or rel.endswith("/" + p)


def _normalize(eco: str, name: str) -> str:
    name = name.lower()
    return re.sub(r"[_.]", "-", name) if eco == "pypi" else name


def _strip_ver(spec: str) -> str:
    return spec.lstrip("^~=<>v ")


def _obj(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def _parse_json(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None


def _classify_npm_spec(spec: str) -> str:
    if spec.startswith(("workspace:", "file:", "link:", "npm:")):
        return ""
    if spec in ("latest", "*", "", "x"):
        return "high"
    if spec.startswith(("git+", "git:", "http:", "https:", "github:")):
        return "high"
    if spec[0] in "^~><" or "*" in spec or spec.endswith(".x") or "||" in spec or " - " in spec:
        return "medium"
    return ""


RE_REQ_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")
RE_NUGET = re.compile(r'<PackageReference\s+Include="([^"]+)"[^>]*?\sVersion="([^"]*)"')
RE_NODE = re.compile(r"^v?(\d+)")
RE_MAJMIN = re.compile(r"^(\d+)\.(\d+)")
RE_PY_RT = re.compile(r"python-(\d+)\.(\d+)")
RE_FROM = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*(node|php|python):v?(\d+)(?:\.(\d+))?", re.I)
RE_USES = re.compile(r"""^\s*-?\s*uses:\s*['"]?([^\s'"#]+)""")
RE_SHA = re.compile(r"^[0-9a-f]{40}$")


class Engine:
    def __init__(self, today: date, extra_blocklist: list | None):
        d = _rules_dir()
        self.meta = _load(d, "meta.json")
        sf = _load(d, "secrets.json")
        self.placeholders = sf["placeholders"]
        self.secrets = [(r, _compile(r["pattern"], r.get("flags", ""))) for r in sf["patterns"]]
        self.patterns = [(r, _compile(r["pattern"], r.get("flags", ""))) for r in _load(d, "patterns.json")]
        self.cycles = _load(d, "eol.json")["cycles"]
        self.blocklist = _load(d, "compromised.json") + (extra_blocklist or [])
        self.today = today
        self.files: set[str] = set()
        self.findings: list[dict] = []

    def add(self, rule: str, severity: str, file: str, line: int, message: str, fix: str = "") -> None:
        self.findings.append({"rule": rule, "name": self.meta[rule]["name"], "severity": severity, "file": file,
                              "line": line, "message": message, "fix": fix or self.meta[rule]["fix"]})

    def _placeholder(self, m: str) -> bool:
        lm = m.lower()
        return any(p in lm for p in self.placeholders)

    def check_compromised(self, eco: str, name: str, version: str, file: str, line: int) -> None:
        n = _normalize(eco, name)
        for b in self.blocklist:
            if b["ecosystem"] != eco or _normalize(eco, b["name"]) != n:
                continue
            if version in b["versions"]:
                self.add("RD003", "critical", file, line,
                         f"{name}@{version} is a known-compromised release: {b['reason']}")
                return

    def check_package_json(self, rel: str, text: str) -> None:
        pj = _parse_json(text)
        if not isinstance(pj, dict):
            return
        count = 0
        for sec in ("dependencies", "devDependencies", "optionalDependencies"):
            m = _obj(pj.get(sec))
            for name in sorted(m):
                spec = m[name]
                if not isinstance(spec, str):
                    continue
                count += 1
                line = _find_key_line(text, name)
                c = _classify_npm_spec(spec)
                if c == "high":
                    self.add("RD001", "high", rel, line, f'"{name}" uses "{spec}", which can resolve to unreviewed or attacker-controlled code')
                elif c == "medium":
                    self.add("RD001", "medium", rel, line, f'"{name}" uses the range "{spec}"; a hijacked release would be pulled in automatically')
                self.check_compromised("npm", name, _strip_ver(spec), rel, line)
        if count > 0:
            d = os.path.dirname(rel) or "."
            lockfiles = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock")
            if not any(os.path.normpath(os.path.join(d, lf)).replace("\\", "/") in self.files for lf in lockfiles):
                self.add("RD002", "medium", rel, 1, "package.json has dependencies but no lockfile is committed")

    def check_package_lock(self, rel: str, text: str) -> None:
        pl = _parse_json(text)
        pkgs = _obj(pl.get("packages") if isinstance(pl, dict) else None)
        for k in sorted(pkgs):
            if k == "":
                continue
            i = k.rfind("node_modules/")
            name = k[i + len("node_modules/"):] if i >= 0 else k
            v = _obj(pkgs[k]).get("version")
            if isinstance(v, str):
                self.check_compromised("npm", name, v, rel, _find_line(text, f'"{k}"'))

    def check_requirements(self, rel: str, text: str) -> None:
        has_dep = False
        for i, raw in enumerate(text.split("\n")):
            line = raw.strip().rstrip("\\").strip()
            if line == "" or line.startswith(("#", "-", "git+", "http")) or " @ " in line:
                continue
            k = line.find(" #")
            if k >= 0:
                line = line[:k].strip()
            k = line.find(";")
            if k >= 0:
                line = line[:k].strip()
            m = RE_REQ_NAME.match(line)
            if not m:
                continue
            has_dep = True
            k = line.find("==")
            if k >= 0:
                ver = line[k + 2:].strip().lstrip("=").strip()
                self.check_compromised("pypi", m.group(0), ver, rel, i + 1)
            else:
                self.add("RD001", "medium", rel, i + 1, f'"{m.group(0)}" is not pinned with ==; installs can silently change')
        if has_dep and "--hash=" not in text:
            self.add("RD002", "low", rel, 1, "requirements file has no --hash entries, so artifacts are not verified")

    def check_csproj(self, rel: str, text: str) -> None:
        for i, l in enumerate(text.split("\n")):
            m = RE_NUGET.search(l)
            if m and ("*" in m.group(2) or "," in m.group(2)):
                self.add("RD001", "medium", rel, i + 1, f'NuGet package "{m.group(1)}" uses the floating version "{m.group(2)}"',
                         "Pin an exact version, enable lock files (<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>) and restore with --locked-mode.")

    def check_secrets(self, rel: str, text: str) -> None:
        for i, l in enumerate(text.split("\n")):
            if "riskdebt-ignore" in l:
                continue
            for r, rx in self.secrets:
                m = rx.search(l)
                if not m:
                    continue
                if r.get("skipPlaceholders") and self._placeholder(m.group(0)):
                    continue
                self.add("RD004", r["severity"], rel, i + 1, f"Possible {r['name']} committed to source")

    def check_patterns(self, rel: str, ext: str, text: str) -> None:
        active = [(r, rx) for r, rx in self.patterns if ext in r["exts"]]
        if not active:
            return
        for i, l in enumerate(text.split("\n")):
            if "riskdebt-ignore" in l:
                continue
            for r, rx in active:
                m = rx.search(l)
                if not m or (r.get("skipPlaceholders") and self._placeholder(m.group(0))):
                    continue
                self.add("RD008", r["severity"], rel, i + 1, f"[{r['framework']}] {r['name']}", r["fix"])

    def eol_finding(self, rel: str, line: int, product: str, ver: str) -> None:
        d = self.cycles.get(f"{product}:{ver}")
        if not d:
            return
        eol = date.fromisoformat(d)
        days = (eol - self.today).days
        if eol < self.today:
            self.add("RD005", "high", rel, line, f"{product} {ver} reached end-of-life on {d} and no longer receives security fixes")
        elif days <= 180:
            self.add("RD005", "medium", rel, line, f"{product} {ver} reaches end-of-life on {d} (in {days} days)")

    def check_eol(self, rel: str, base: str, text: str) -> None:
        first = text.split("\n")[0].strip()
        if base in (".nvmrc", ".node-version"):
            m = RE_NODE.match(first)
            if m:
                self.eol_finding(rel, 1, "node", m.group(1))
        elif base in (".python-version", ".php-version"):
            m = RE_MAJMIN.match(first)
            if m:
                self.eol_finding(rel, 1, "python" if base == ".python-version" else "php", f"{m.group(1)}.{m.group(2)}")
        elif base == "runtime.txt":
            m = RE_PY_RT.search(first)
            if m:
                self.eol_finding(rel, 1, "python", f"{m.group(1)}.{m.group(2)}")
        if base == "Dockerfile" or base.startswith("Dockerfile.") or base.endswith(".dockerfile"):
            for i, l in enumerate(text.split("\n")):
                f = RE_FROM.match(l)
                if not f:
                    continue
                product = f.group(1).lower()
                if product == "node":
                    self.eol_finding(rel, i + 1, product, f.group(2))
                elif f.group(3) is not None:
                    self.eol_finding(rel, i + 1, product, f"{f.group(2)}.{f.group(3)}")

    def check_claude_settings(self, rel: str, text: str) -> None:
        perm = _obj(_obj(_parse_json(text)).get("permissions"))
        allow = perm.get("allow")
        if isinstance(allow, list):
            for a in allow:
                if a in ("*", "Bash", "Bash(*)"):
                    self.add("RD006", "high", rel, _find_line(text, f'"{a}"'),
                             f'Agent is allowed to run "{a}" without approval (unrestricted shell access)',
                             'Allow only specific commands, e.g. "Bash(npm test)", and keep prompts for anything that writes, deletes or reaches the network.')
        if perm.get("defaultMode") == "bypassPermissions":
            self.add("RD006", "high", rel, _find_line(text, '"bypassPermissions"'),
                     "Agent permission mode is bypassPermissions, so every action runs without human approval",
                     "Use the default or acceptEdits mode and reserve bypass for disposable sandboxes without credentials.")

    def check_mcp(self, rel: str, text: str) -> None:
        s = _obj(_parse_json(text))
        servers = _obj(s.get("mcpServers")) if s.get("mcpServers") else _obj(s.get("servers"))
        for name in sorted(servers):
            srv = _obj(servers[name])
            cmd = srv.get("command") if isinstance(srv.get("command"), str) else ""
            args = srv.get("args") if isinstance(srv.get("args"), list) else []
            if cmd in ("npx", "uvx", "bunx"):
                for arg in args:
                    if not isinstance(arg, str) or arg == "" or arg.startswith("-"):
                        continue
                    pinned = arg.rfind("@") > 0
                    if cmd == "uvx":
                        pinned = pinned or "==" in arg
                    if not pinned:
                        self.add("RD006", "medium", rel, _find_line(text, f'"{arg}"'),
                                 f"MCP server \"{name}\" runs {cmd} {arg} with no version pin, so a compromised release executes with your agent's access",
                                 'Pin the version (e.g. "pkg@1.2.3") and review updates before bumping.')
                    break
            env = _obj(srv.get("env"))
            for k in sorted(env):
                v = env[k] if isinstance(env[k], str) else ""
                uk = k.upper()
                if v == "" or v.startswith("$"):
                    continue
                if any(w in uk for w in ("TOKEN", "KEY", "SECRET", "PASSWORD")):
                    self.add("RD006", "high", rel, _find_line(text, f'"{k}"'),
                             f'MCP server "{name}" has a literal credential in {k}',
                             f'Reference it as "${{{k}}}" and keep the value in your shell or secret manager, never in a committed file.')

    def check_workflow(self, rel: str, text: str) -> None:
        for i, l in enumerate(text.split("\n")):
            m = RE_USES.match(l)
            if not m or m.group(1).startswith(("./", "docker://")):
                continue
            k = m.group(1).rfind("@")
            ref = m.group(1)[k + 1:] if k >= 0 else ""
            if not RE_SHA.match(ref):
                self.add("RD007", "medium", rel, i + 1,
                         f'Action {m.group(1)} is not pinned to a commit SHA (ref "{ref}" can be moved by its owner)')


def _walk(root: Path, d: Path, out: list) -> None:
    for entry in sorted(os.scandir(d), key=lambda e: e.name):
        if entry.is_dir(follow_symlinks=False):
            if entry.name not in SKIP_DIRS:
                _walk(root, Path(entry.path), out)
        elif entry.is_file(follow_symlinks=False):
            out.append((Path(entry.path).relative_to(root).as_posix(), Path(entry.path)))


def scan(root: str, today: date | None = None, extra_blocklist: list | None = None) -> dict:
    if today is None:
        today = datetime.now(timezone.utc).date()
    e = Engine(today, extra_blocklist)
    rootp = Path(root)
    items: list = []
    _walk(rootp, rootp, items)
    for rel, _ in items:
        e.files.add(rel)
    scanned = 0
    for rel, abs_ in items:
        base = rel.rsplit("/", 1)[-1]
        ext = _ext(base)
        if base == "Dockerfile" or base.startswith("Dockerfile."):
            ext = ".dockerfile"
        if ext in BINARY_EXTS:
            continue
        try:
            if abs_.stat().st_size > MAX_FILE_SIZE:
                continue
            data = abs_.read_bytes()
        except OSError:
            continue
        if b"\x00" in data[:8000]:
            continue
        text = data.decode("utf-8", errors="replace")
        scanned += 1
        if base == "package.json":
            e.check_package_json(rel, text)
        elif base == "package-lock.json":
            e.check_package_lock(rel, text)
        elif base.startswith("requirements") and ext == ".txt":
            e.check_requirements(rel, text)
        elif ext == ".csproj":
            e.check_csproj(rel, text)
        e.check_secrets(rel, text)
        e.check_patterns(rel, ext, text)
        e.check_eol(rel, base, text)
        if _ends_with_path(rel, ".claude/settings.json") or _ends_with_path(rel, ".claude/settings.local.json"):
            e.check_claude_settings(rel, text)
        if base == ".mcp.json" or _ends_with_path(rel, ".cursor/mcp.json") or _ends_with_path(rel, ".vscode/mcp.json"):
            e.check_mcp(rel, text)
        if "/.github/workflows/" in "/" + rel and ext in (".yml", ".yaml"):
            e.check_workflow(rel, text)
    e.findings.sort(key=lambda f: (f["file"], f["line"], f["rule"], f["message"]))
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in e.findings:
        summary[f["severity"]] += 1
    return {"tool": "riskdebt", "version": VERSION, "root": root, "scanned": scanned,
            "findings": e.findings, "summary": summary}
