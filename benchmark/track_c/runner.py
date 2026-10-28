"""Track C runner — real-target precision benchmark."""
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import time
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
RUNS = HERE / "runs"

CSRF_RE = re.compile(r"""name=['"]user_token['"]\s+value=['"]([^'"]+)['"]""")


def load_cases(app: str) -> list[dict]:
    with open(HERE / "cases.csv", newline="") as f:
        return [row for row in csv.DictReader(f) if row["app"] == app]


def load_apps() -> dict:
    return json.loads((HERE / "apps.json").read_text(encoding="utf-8"))


def _csrf(html: str) -> str | None:
    m = CSRF_RE.search(html)
    return m.group(1) if m else None


def _login_once(s: requests.Session, base: str, login_cfg: dict) -> tuple[bool, str]:
    r = s.get(base + login_cfg["url"], timeout=10)
    tok = _csrf(r.text)
    data = dict(login_cfg["data"])
    if tok:
        data["user_token"] = tok
    r = s.post(base + login_cfg["url"], data=data, timeout=10, allow_redirects=True)
    if "CSRF token is incorrect" in r.text:
        return False, "csrf incorrect"
    if "login.php" in r.url:
        return False, f"still on login ({r.url})"
    return True, r.url


def _dvwa_setup(s: requests.Session, base: str) -> bool:
    r = s.get(base + "/setup.php", timeout=10)
    if "Create / Reset Database" not in r.text:
        return False
    tok = _csrf(r.text)
    data = {"create_db": "Create / Reset Database"}
    if tok:
        data["user_token"] = tok
    r = s.post(base + "/setup.php", data=data, timeout=20, allow_redirects=True)
    print(f"  DVWA setup POST /setup.php -> {r.status_code}")
    return True


def login(cfg: dict) -> requests.Session:
    s = requests.Session()
    login_cfg = cfg.get("login")
    if not login_cfg:
        return s
    base = cfg["base_url"]

    ok, where = _login_once(s, base, login_cfg)
    print(f"  login #1 -> ok={ok}, where={where}")
    if not ok:
        raise SystemExit(f"login failed: {where}")

    if "setup.php" in where:
        print("  first-run: DVWA database not initialised, creating")
        _dvwa_setup(s, base)
        s = requests.Session()
        ok, where = _login_once(s, base, login_cfg)
        print(f"  login #2 -> ok={ok}, where={where}")
        if not ok:
            raise SystemExit(f"login failed after setup: {where}")

    if "post_url" in login_cfg:
        r = s.get(base + login_cfg["post_url"], timeout=10)
        tok = _csrf(r.text)
        data = dict(login_cfg["post_data"])
        if tok:
            data["user_token"] = tok
        r = s.post(base + login_cfg["post_url"], data=data, timeout=10, allow_redirects=True)
        print(f"  security set -> {r.status_code}, url={r.url}")

    verify_url = base + "/vulnerabilities/sqli/?id=1"
    rv = s.get(verify_url, timeout=10, allow_redirects=True)
    if "login.php" in rv.url:
        raise SystemExit(f"not authenticated: {rv.url}")
    if len(rv.text) < 500:
        raise SystemExit(f"auth verification: {rv.status_code}, {len(rv.text)}B too small")
    print(f"  auth OK: {verify_url} -> {rv.status_code}, {len(rv.text)}B")

    return s


def wait_healthy(cfg: dict, timeout_s: int = 90) -> None:
    base = cfg["base_url"]
    url = base + cfg["healthcheck"]
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=3, allow_redirects=True)
            if r.status_code < 500:
                print(f"  healthy: {url} -> {r.status_code}")
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    raise SystemExit(f"{url} never became healthy")


def scan_case(cfg: dict, session: requests.Session, case: dict, out_dir: Path) -> None:
    base = cfg["base_url"]
    url = base + case["path"]  # path carries the full query string (DVWA needs Submit=Submit, etc.)
    cmd = [
        "janissary", "scan",
        "-u", url,
        "-p", case["param"],
        "--method", case["method"],
        "--jsonl", "--quiet",
        "--no-waf",
    ]
    if session.cookies:
        cookie_hdr = "; ".join(f"{c.name}={c.value}" for c in session.cookies)
        cmd += ["--cookie", cookie_hdr]
    out = out_dir / f"{case['vuln_class']}.jsonl"
    err = out_dir / f"{case['vuln_class']}.stderr"
    try:
        with open(out, "w", encoding="utf-8") as fout, open(err, "w", encoding="utf-8") as ferr:
            proc = subprocess.run(cmd, stdout=fout, stderr=ferr, timeout=180)
        sz = out.stat().st_size
        line = f"  {case['method']} {case['path']} param={case['param']} ({case['vuln_class']}) -> exit {proc.returncode}, {sz}B"
        if proc.returncode not in (0, 1):
            with open(err, encoding="utf-8") as f:
                preview = f.read(500).strip().replace("\n", " ")
            if preview:
                line += f"   [stderr: {preview[:200]}]"
        print(line)
    except subprocess.TimeoutExpired:
        print(f"  {case['method']} {case['path']} ({case['vuln_class']}) -> TIMEOUT")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", required=True, choices=["dvwa", "juice-shop"])
    args = ap.parse_args()

    apps = load_apps()
    if args.app not in apps:
        raise SystemExit(f"unknown app: {args.app}")
    cfg = apps[args.app]
    cases = load_cases(args.app)
    if not cases:
        raise SystemExit(f"no cases for {args.app}")

    print(f"[track_c] app={args.app} cases={len(cases)}")
    wait_healthy(cfg)
    session = login(cfg)

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out_dir = RUNS / f"{stamp}-{args.app}"
    out_dir.mkdir(parents=True)
    print(f"[track_c] run dir: {out_dir}")

    for c in cases:
        scan_case(cfg, session, c, out_dir)

    (out_dir / "manifest.json").write_text(json.dumps({
        "app": args.app,
        "cases": len(cases),
        "stamp": stamp,
    }, indent=2))
    print(f"[track_c] done: {out_dir}")


if __name__ == "__main__":
    main()
