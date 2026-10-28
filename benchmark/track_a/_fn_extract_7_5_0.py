#!/usr/bin/env python3
"""_fn_extract_7_5_0.py -- compute FN-only CSV from a completed run.

Mirrors run_with_recovery.py's FN-set logic:
  - 'fired' = testnames with at least one finding (regardless of family)
  - 'FN candidates' = vulnerable==true AND testname not in fired

Does NOT exclude DAST-excluded categories. Matching run_with_recovery.py
line 143-148: this is deliberate (the recovery pass reruns whatever the
baseline missed, including excluded categories; scoring excludes them).

Usage:
    python benchmark/track_a/_fn_extract_7_5_0.py \
        --run-dir benchmark/track_a/runs/<run> \
        --cases-csv benchmark/track_a/case_vectors.csv \
        --out benchmark/track_a/_chunks/fn_recovery_7_5_0.csv
"""
from __future__ import annotations
import argparse
import csv
import json
import re
from pathlib import Path


def fired_testnames(findings_path: Path) -> set[str]:
    fired: set[str] = set()
    if not findings_path.exists():
        return fired
    for line in findings_path.read_text(encoding="utf-8").splitlines():
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True, type=Path)
    ap.add_argument("--cases-csv", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    fired = fired_testnames(args.run_dir / "findings.jsonl")
    print(f"fired testnames in {args.run_dir.name}: {len(fired)}")

    with args.cases_csv.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        fieldnames = reader.fieldnames
        cases = list(reader)

    print(f"cases in csv: {len(cases)}")
    vuln_total = sum(1 for c in cases if (c.get("vulnerable") or "").strip().lower() == "true")
    print(f"vulnerable==true: {vuln_total}")

    fn_cases = [
        c for c in cases
        if c["testname"] not in fired
        and (c.get("vulnerable") or "").strip().lower() == "true"
    ]
    print(f"FN candidates (vulnerable, not fired): {len(fn_cases)}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        for c in fn_cases:
            w.writerow(c)
    print(f"wrote {len(fn_cases)} rows -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())