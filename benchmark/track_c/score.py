"""Track C scorer — classify findings against known cases."""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUNS = HERE / "runs"

CLASS_MAP = {
    "sqli": {"sqli", "sqli:sql_injection", "sqli:error", "sqli:union", "sqli:time_based", "sqli:reflection"},
    "sqli_blind": {"sqli", "sqli:sql_injection", "sqli:blind", "sqli:time_based"},
    "xss": {"xss", "xss:reflected", "xss:stored", "xss:dom", "xss:reflection"},
    "cmdi": {"cmdi", "cmdi:command_injection", "cmdi:cmd_injection"},
    "traversal": {"traversal", "pathtraver", "pathtraver:path_traversal", "pathtraver:file_inclusion", "traversal:path_traversal"},
}


def load_cases(app: str) -> list[dict]:
    with open(HERE / "cases.csv", newline="") as f:
        return [row for row in csv.DictReader(f) if row["app"] == app]


def collect_findings(run_dir: Path) -> list[dict]:
    findings = []
    for jl in run_dir.glob("*.jsonl"):
        case_class = jl.stem
        for line in jl.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            rec["_case_class"] = case_class
            findings.append(rec)
    return findings


def category_of(f: dict) -> str:
    return f.get("class") or f.get("category") or f.get("rule_id") or f.get("ruleId") or ""


def matches(f: dict, case: dict) -> bool:
    expected = CLASS_MAP.get(case["vuln_class"], set())
    return category_of(f) in expected


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", required=True)
    ap.add_argument("--run", help="path to run dir (default: latest for app)")
    args = ap.parse_args()

    if args.run:
        run_dir = Path(args.run)
    else:
        candidates = sorted(RUNS.glob(f"*-{args.app}"))
        if not candidates:
            raise SystemExit(f"no runs for {args.app}")
        run_dir = candidates[-1]
    if not run_dir.is_dir():
        raise SystemExit(f"run dir not found: {run_dir}")

    cases = load_cases(args.app)
    findings = collect_findings(run_dir)

    tp = 0
    matched_case_keys = set()
    fp = 0
    for f in findings:
        # The case this finding came from
        same_class_cases = [c for c in cases if c["vuln_class"] == f["_case_class"]]
        if any(matches(f, c) for c in same_class_cases):
            tp += 1
            matched_case_keys.add(f["_case_class"])
        else:
            fp += 1

    tp = len(matched_case_keys)
    fn = len(cases) - len(matched_case_keys)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = len(matched_case_keys) / len(cases) if cases else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    summary = {
        "app": args.app,
        "run": str(run_dir),
        "cases": len(cases),
        "findings": len(findings),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }
    print(json.dumps(summary, indent=2))
    (run_dir / "score.json").write_text(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
