"""Convert OWASP Benchmark expectedresults CSV into the standardized
cases.csv format that benchmark/common/ground_truth.py expects.

OWASP CSV shape (no header row, first line is a comment):
    # test name, category, real vulnerability, cwe, ...
    BenchmarkTest00001,pathtraver,true,22
    BenchmarkTest00002,pathtraver,true,22
    ...

Standardized output:
    testname,category,vulnerable,cwe
    BenchmarkTest00001,pathtraver,true,22
    ...

Usage:
    python -m benchmark.track_a.adapt_ground_truth \
        --input /path/to/expectedresults-1.2.csv \
        --output benchmark/track_a/cases.csv
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path


def adapt(input_path: Path, output_path: Path) -> int:
    written = 0
    with input_path.open("r", encoding="utf-8", newline="") as fin, \
         output_path.open("w", encoding="utf-8", newline="") as fout:
        reader = csv.reader(fin)
        writer = csv.writer(fout)
        writer.writerow(["testname", "category", "vulnerable", "cwe"])
        for row in reader:
            if not row:
                continue
            first = row[0].strip()
            if first.startswith("#") or not first:
                continue
            if len(row) < 4:
                continue
            testname = first
            category = row[1].strip()
            vuln_raw = row[2].strip().lower()
            if vuln_raw not in ("true", "false"):
                continue
            cwe = row[3].strip()
            writer.writerow([testname, category, vuln_raw, cwe])
            written += 1
    return written


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="benchmark.track_a.adapt_ground_truth")
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    n = adapt(args.input, args.output)
    print(f"[adapt] wrote {n} cases -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())