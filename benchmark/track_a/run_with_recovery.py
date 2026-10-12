#!/usr/bin/env python3
"""run_with_recovery.py -- FN recovery pass on top of a Track A runner run.

Reproduces the Amendment 20 protocol. Runs the runner once on the
requested CSV, computes the zero-finding subset, runs a second pass on
that subset, and merges both findings files into a recovered run dir.

Usage:
    python benchmark/track_a/run_with_recovery.py `
        --target-base http://127.0.0.1:8080/benchmark `
        --cases-csv benchmark/track_a/_chunks/full_p0.csv `
        --tools-env benchmark/track_a/tools_env_default.txt
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RUNS = REPO / "benchmark" / "track-a" / "runs"
RUNNER = REPO / "benchmark" / "track_a" / "runner.py"


def _snapshot_runs() -> set[str]:
    return {p.name for p in RUNS.iterdir() if p.is_dir()}


def _new_run(before: set[str]) -> Path:
    after = {p.name for p in RUNS.iterdir() if p.is_dir()}
    new = after - before
    if len(new) != 1:
        raise SystemExit(f"expected 1 new run dir, got {len(new)}: {sorted(new)}")
    return RUNS / new.pop()


def _invoke_runner(target_base: str, cases_csv: Path, tools_env: Path) -> Path:
    before = _snapshot_runs()
    cmd = [
        sys.executable, str(RUNNER),
        "--tool", "janissary",
        "--run-number", "1",
        "--target-base", target_base,
        "--cases-csv", str(cases_csv),
        "--tools-env", str(tools_env),
    ]
    print(f"[recovery] invoking: {' '.join(cmd)}", flush=True)
    rc = subprocess.run(cmd, cwd=str(REPO), check=False).returncode
    if rc not in (0, 1):
        raise SystemExit(f"runner exit code {rc}; aborting")
    return _new_run(before)


def _fired_cases(run_dir: Path) -> set[str]:
    findings = run_dir / "findings.jsonl"
    if not findings.exists():
        return set()
    fired: set[str] = set()
    for line in findings.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = obj.get("url") or ""
        m = re.search(r"BenchmarkTest(\d+)", url)
        if m:
            fired.add("BenchmarkTest" + m.group(1))
    return fired


def _all_cases(csv_path: Path) -> list[dict]:
    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _write_subset(cases: list[dict], out_path: Path) -> None:
    fieldnames = ["testname", "category", "urlpath", "mode", "header_name", "vulnerable"]
    with out_path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for c in cases:
            w.writerow(c)


def _merge(pass1: Path, pass2: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    out_findings = out_dir / "findings.jsonl"
    with out_findings.open("wb") as out_fh:
        for src in (pass1 / "findings.jsonl", pass2 / "findings.jsonl"):
            if src.exists():
                data = src.read_bytes()
                out_fh.write(data)
                if data and not data.endswith(b"\n"):
                    out_fh.write(b"\n")
    m_src = pass2 / "manifest.json"
    if m_src.exists():
        (out_dir / "manifest.json").write_bytes(m_src.read_bytes())


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--target-base", required=True)
    p.add_argument("--cases-csv", required=True, type=Path)
    p.add_argument("--tools-env", required=True, type=Path)
    args = p.parse_args()

    if not args.cases_csv.exists():
        raise SystemExit(f"cases csv not found: {args.cases_csv}")

    all_cases = _all_cases(args.cases_csv)
    print(f"[recovery] cases in csv: {len(all_cases)}", flush=True)

    print("[recovery] === pass 1 ===", flush=True)
    run1 = _invoke_runner(args.target_base, args.cases_csv, args.tools_env)
    print(f"[recovery] pass 1 run dir: {run1.name}", flush=True)

    fired = _fired_cases(run1)
    print(f"[recovery] cases with findings in pass 1: {len(fired)}", flush=True)

    zero_cases = [
        c for c in all_cases
        if c["testname"] not in fired
        and (c.get("vulnerable") or "").strip().lower() == "true"
    ]
    print(f"[recovery] zero-finding vulnerable cases: {len(zero_cases)}", flush=True)

    if not zero_cases:
        print("[recovery] no zero-finding cases; nothing to recover", flush=True)
        return 0

    retry_csv = args.cases_csv.parent / f"_retry_{args.cases_csv.stem}.csv"
    _write_subset(zero_cases, retry_csv)
    print(f"[recovery] retry csv: {retry_csv}", flush=True)

    print("[recovery] === pass 2 ===", flush=True)
    run2 = _invoke_runner(args.target_base, retry_csv, args.tools_env)
    print(f"[recovery] pass 2 run dir: {run2.name}", flush=True)

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    merged = RUNS / f"merged-recovery-{stamp}"
    _merge(run1, run2, merged)
    print(f"[recovery] merged: {merged}", flush=True)

    try:
        retry_csv.unlink()
    except OSError:
        pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
