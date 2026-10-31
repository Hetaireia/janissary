#!/usr/bin/env python
"""Auto-regenerate dashboard from repo state.
Each milestone can have a `probe` describing how to detect completion.
Kinds: file_exists, dir_exists, dir_has_children, glob_exists,
       file_newer_than, grep_any, grep_all, pypi_version_gte, http_200, any_of
"""
import json, re, subprocess, sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / "tools" / "ascension_state.json"
TEMPLATE = ROOT / "tools" / "dashboard-template.html"
OUTPUT = ROOT / "renders" / "dashboard-refined.html"

def sh(*args):
    try: return subprocess.check_output(args, stderr=subprocess.DEVNULL).decode().strip()
    except Exception: return ""

def mtime_iso(p):
    try: return datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d")
    except Exception: return datetime.utcnow().strftime("%Y-%m-%d")

def probe_version():
    p = ROOT / "pyproject.toml"
    if not p.exists(): return "unknown"
    m = re.search(r'^version\s*=\s*"([^"]+)"', p.read_text(encoding="utf-8"), re.M)
    return m.group(1) if m else "unknown"

def probe_corpus_f1():
    p = ROOT / "benchmark" / "track_c" / "corpus-score.json"
    if not p.exists(): return "n/a"
    try: return str(json.loads(p.read_text(encoding="utf-8"))["totals"]["f1"])
    except Exception: return "n/a"

def evaluate(probe):
    kind = probe.get("kind")
    if kind == "file_exists":
        p = ROOT / probe["path"]; return mtime_iso(p) if p.exists() else None
    if kind == "dir_exists":
        p = ROOT / probe["path"]; return mtime_iso(p) if p.is_dir() else None
    if kind == "dir_has_children":
        p = ROOT / probe["path"]
        if p.is_dir():
            kids = list(p.iterdir())
            if len(kids) >= probe.get("min", 1):
                return max(mtime_iso(k) for k in kids)
        return None
    if kind == "glob_exists":
        matches = []
        for pat in probe["pattern"].split(","):
            matches.extend(ROOT.glob(pat.strip()))
        return max((mtime_iso(x) for x in matches), default=None)
    if kind == "git_commits_touching":
        since = probe.get("since", "1970-01-01")
        out = sh("git", "-C", str(ROOT), "log", "--all", f"--since={since}",
                 "--format=%aI", "--", probe["pattern"])
        lines = [l for l in out.splitlines() if l]
        return lines[0][:10] if lines else None
    if kind == "file_newer_than":
        since = probe["since"]; matches = []
        for pat in probe["pattern"].split(","):
            matches.extend(ROOT.glob(pat.strip()))
        recent = [x for x in matches if mtime_iso(x) >= since]
        return max((mtime_iso(x) for x in recent), default=None)
    if kind == "grep_any":
        for path in probe["paths"]:
            p = ROOT / path
            if not p.exists(): continue
            text = p.read_text(encoding="utf-8", errors="ignore").lower()
            if any(pat.lower() in text for pat in probe["patterns"]):
                return mtime_iso(p)
        return None
    if kind == "grep_all":
        for path in probe["paths"]:
            p = ROOT / path
            if not p.exists(): continue
            text = p.read_text(encoding="utf-8", errors="ignore").lower()
            if all(pat.lower() in text for pat in probe["patterns"]):
                return mtime_iso(p)
        return None
    if kind == "pypi_version_gte":
        try:
            import urllib.request
            with urllib.request.urlopen("https://pypi.org/pypi/janissary/json", timeout=10) as r:
                data = json.load(r)
            from packaging.version import Version
            th = Version(probe["min_version"])
            for v, files in data.get("releases", {}).items():
                try:
                    if Version(v) >= th and files:
                        return files[0]["upload_time"][:10]
                except Exception: pass
        except Exception: return None
        return None
    if kind == "http_200":
        try:
            import urllib.request
            with urllib.request.urlopen(probe["url"], timeout=10) as r:
                if r.status == 200: return datetime.utcnow().strftime("%Y-%m-%d")
        except Exception: return None
        return None
    if kind == "any_of":
        for sub in probe.get("probes", []):
            d = evaluate(sub)
            if d: return d
        return None
    return None

def resolve(mid, m):
    if m.get("delivered"): return m["delivered"]
    if not m.get("probe"): return None
    return evaluate(m["probe"])

def fmt_date(iso):
    if not iso: return "&mdash;"
    return datetime.strptime(iso[:10], "%Y-%m-%d").strftime("%d-%b-%Y").upper()

def fmt_ts(iso):
    return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S").strftime("%d-%b-%Y %H:%M:%S").upper()

def fmt_target(iso):
    return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S").strftime("%d-%b-%Y").upper()

def build_rows(state):
    rows, delivered, total = [], 0, 0
    for phase in state["phases"]:
        rows.append(f'      <div class="phase">{phase["name"]}</div>')
        for mid in phase["milestones"]:
            total += 1
            m = state["milestones"].get(mid, {})
            d = resolve(mid, m)
            if d: delivered += 1
            tick = "tick on" if d else "tick"
            glyph = "&check;" if d else ""
            cls = "m-date done" if d else "m-date"
            rows.append(
                f'      <div class="row data">'
                f'<div class="cell-status"><span class="{tick}">{glyph}</span>'
                f'<span class="m-id">{mid}</span></div>'
                f'<div class="m-name">{m.get("label","")}</div>'
                f'<div class="m-date">{m.get("proposed","?")}</div>'
                f'<div class="{cls}">{fmt_date(d)}</div></div>'
            )
    pct = round(delivered / total * 100, 1) if total else 0.0
    return "\n".join(rows), pct

def render(state):
    template = TEMPLATE.read_text(encoding="utf-8")
    rows, pct = build_rows(state)
    subs = {
        "{{HEAD}}": sh("git", "-C", str(ROOT), "rev-parse", "--short", "HEAD") or "unknown",
        "{{VERSION}}": probe_version(),
        "{{CORPUS_F1}}": probe_corpus_f1(),
        "{{CREATED_DISPLAY}}": fmt_ts(state["created"]),
        "{{TARGET_DISPLAY}}": fmt_target(state["target"]),
        "{{CREATION_ISO}}": state["created"],
        "{{TARGET_ISO}}": state["target"],
        "{{WORK_PCT}}": str(pct),
        "{{MILESTONE_ROWS}}": rows,
    }
    for k, v in subs.items(): template = template.replace(k, v)
    return template, pct

def main():
    state = json.loads(STATE.read_text(encoding="utf-8"))
    html, pct = render(state)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    if "--check" in sys.argv:
        if not OUTPUT.exists(): sys.exit(f"missing: {OUTPUT}")
        if OUTPUT.read_text(encoding="utf-8") != html:
            sys.exit("stale: run python tools/ascension.py")
        print(f"OK: {OUTPUT}"); return
    OUTPUT.write_text(html, encoding="utf-8")
    print(f"wrote {OUTPUT} ({len(html)} chars, work={pct}%)")

if __name__ == "__main__":
    main()