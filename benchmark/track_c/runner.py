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

    if "capture_jwt_from_json" in login_cfg:
        if "pre_register" in login_cfg:
            pr = login_cfg["pre_register"]
            try:
                s.post(base + pr["url"], json=pr["json"], timeout=10)
            except requests.RequestException as e:
                print(f"  pre_register failed: {e}")
        r = s.post(base + login_cfg["url"], json=login_cfg["data"], timeout=10)
        if r.status_code != 200:
            raise SystemExit(f"login POST failed: {r.status_code}")
        try:
            resp = r.json()
        except Exception as e:
            raise SystemExit(f"login response not JSON: {e}")
        jwt_field = login_cfg["capture_jwt_from_json"]
        jwt = resp.get(jwt_field)
        if not jwt:
            raise SystemExit(f"login missing field {jwt_field!r}; keys={list(resp.keys())}")
        s._jns_bearer = jwt
        print(f"  JWT captured from {jwt_field!r}: {len(jwt)} chars")
        return s

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

    verify_url = base + cfg.get("verify_url", "/vulnerabilities/sqli/?id=1")
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


def _dedupe_jsonl(path: Path) -> int:
    """Keep at most one row per fingerprint in the JSONL at `path`.

    The scanner emits one row per (payload, url, class) hit; trial-level
    semantics want one row per (fingerprint). Returns number of dropped rows.
    """
    if not path.exists() or path.stat().st_size == 0:
        return 0
    lines = path.read_text(encoding="utf-8").splitlines()
    kept, seen = [], set()
    for line in lines:
        s = line.strip()
        if not s:
            continue
        try:
            rec = json.loads(s)
        except json.JSONDecodeError:
            kept.append(s); continue
        fp = rec.get("fingerprint")
        if fp is None or fp not in seen:
            seen.add(fp) if fp is not None else None
            kept.append(s)
    dropped = len(lines) - len(kept)
    if dropped:
        path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    return dropped


def scan_case(cfg: dict, session: requests.Session, case: dict, out_dir: Path) -> dict:
    base = cfg["base_url"]
    url = base + case["path"]
    cmd = [
        "janissary", "scan",
        "-u", url,
        "-p", case["param"],
        "--method", case["method"],
        "--jsonl", "--quiet",
        "--no-waf",
    ]
    _notes = case.get("notes", "") or ""
    if "json_body:" in _notes:
        _template_rel = _notes.split("json_body:", 1)[1].split(",")[0].strip()
        _template_abs = Path(__file__).parent / _template_rel
        cmd += ["--inject-in", "json-body", "--json-template", str(_template_abs)]
    if hasattr(session, "_jns_bearer") and session._jns_bearer:
        cmd += ["--bearer", session._jns_bearer]
    if session.cookies:
        cookie_hdr = "; ".join(f"{c.name}={c.value}" for c in session.cookies)
        cmd += ["--cookie", cookie_hdr]
    out = out_dir / f"{case['vuln_class']}.jsonl"
    err = out_dir / f"{case['vuln_class']}.stderr"
    record = {
        "path": case["path"],
        "method": case["method"],
        "param": case["param"],
        "vuln_class": case["vuln_class"],
        "safe": (case.get("safe") or "false").strip().lower() == "true",
        "exit": None,
        "out_bytes": 0,
        "dropped": 0,
        "aborted": False,
    }
    try:
        with open(out, "w", encoding="utf-8") as fout, open(err, "w", encoding="utf-8") as ferr:
            proc = subprocess.run(cmd, stdout=fout, stderr=ferr, timeout=180)
        err_text = ""
        try:
            err_text = err.read_text(encoding="utf-8")
        except OSError:
            pass
        dropped = _dedupe_jsonl(out)
        sz = out.stat().st_size
        aborted = proc.returncode == 2 or "aborted" in err_text
        record.update(exit=proc.returncode, out_bytes=sz, dropped=dropped, aborted=aborted)
        line = f"  {case['method']} {case['path']} param={case['param']} ({case['vuln_class']}) -> exit {proc.returncode}, {sz}B"
        if dropped:
            line += f" [dedupe: -{dropped}]"
        if aborted and proc.returncode not in (0, 1):
            preview = err_text.strip().replace("\n", " ")[:200]
            if preview:
                line += f"   [stderr: {preview}]"
        print(line)
    except subprocess.TimeoutExpired:
        print(f"  {case['method']} {case['path']} ({case['vuln_class']}) -> TIMEOUT")
        record.update(exit=-1, aborted=False)
    return record


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", required=True)  # validated against apps.json below
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

    records = []
    for c in cases:
        records.append(scan_case(cfg, session, c, out_dir))

    (out_dir / "manifest.json").write_text(json.dumps({
        "app": args.app,
        "cases": len(cases),
        "stamp": stamp,
    }, indent=2))
    (out_dir / "exit_codes.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
    print(f"[track_c] done: {out_dir}")


if __name__ == "__main__":
    main()
