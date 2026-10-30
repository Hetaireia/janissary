"""Track C scorer -- per-case TP/FP/FN/TN accounting.

See SCHEMA.md for the trial model. Summary:

- Each row in cases.csv is a trial: (app, path, method, param).
- safe=false trials expect a finding of expected_finding_class.
- safe=true trials expect no findings; any finding on them is FP.
- Findings are matched to trials by URL path (last-segment).
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
RUNS = HERE / "runs"

# Fallback map for backwards compatibility with v1 cases.csv (no
# expected_finding_class column). Preferred path is the column.
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


def load_exit_codes(run_dir: Path) -> dict[str, dict]:
    p = run_dir / "exit_codes.json"
    if not p.exists():
        return {}
    try:
        rows = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    out = {}
    for r in rows:
        try:
            k = str(r["path"]) + "|" + str(r["method"]) + "|" + str(r["param"])
        except KeyError:
            continue
        out[k] = r
    return out


def category_of(f: dict) -> str:
    return f.get("class") or f.get("category") or f.get("rule_id") or f.get("ruleId") or ""


def finding_path(f: dict) -> str:
    url = f.get("url") or ""
    p = urlparse(url).path.rstrip("/")
    return p if p else "/"


def case_path(c: dict) -> str:
    p = c["path"].split("?")[0].rstrip("/")
    return p if p else "/"


def is_safe_case(c: dict) -> bool:
    return (c.get("safe") or "false").strip().lower() == "true"


def finding_matches_case(f: dict, c: dict) -> bool:
    return finding_path(f).endswith(case_path(c))


def _placeholder_path_match(fp: str, cp: str) -> bool:
    """Match a finding path against a case path containing {param} placeholders.

    /users/v1/{username} matches /users/v1/name1 but NOT /users/v1 or
    /users/v1/name1/email (exactly one segment per placeholder).
    """
    import re as _re
    pat = _re.escape(cp)
    pat = _re.sub(r"\\\{[^}]+\\\}", "[^/?#]+", pat)
    return _re.search(pat + r"($|[?#])", fp) is not None


def expected_classes(c: dict) -> set[str]:
    """Classes that count as TP for this case."""
    eff = (c.get("expected_finding_class") or "").strip()
    if eff:
        return {eff}
    vc = (c.get("vuln_class") or "").strip()
    if vc:
        return CLASS_MAP.get(vc, {vc})
    return set()


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
    exit_codes = load_exit_codes(run_dir)

    # Assign each finding to case(s) by class-aware attribution
    by_case: dict[int, list[dict]] = {}
    unmatched_findings = 0
    for f in findings:
        f_class = category_of(f)
        fp = finding_path(f)

        # Priority 1: literal path match (preserves existing behavior
        # for non-placeholder cases).
        literal = [c for c in cases if "{" not in case_path(c) and finding_matches_case(f, c)]
        if literal:
            strict = [c for c in literal if is_safe_case(c) or f_class in expected_classes(c)]
            for c in (strict or literal):
                by_case.setdefault(id(c), []).append(f)
            continue

        # Priority 2: placeholder path match (Phase 1c path-param cases).
        placeholder = [
            c for c in cases
            if "{" in case_path(c) and _placeholder_path_match(fp, case_path(c))
        ]
        if placeholder:
            strict = [c for c in placeholder if is_safe_case(c) or f_class in expected_classes(c)]
            for c in (strict or placeholder):
                by_case.setdefault(id(c), []).append(f)
            continue

        unmatched_findings += 1

    tp = fp = fn = tn = 0
    aborts = 0
    per_case = []
    for c in cases:
        is_safe = (c.get("safe") or "false").strip().lower() == "true"
        cf = by_case.get(id(c), [])
        if is_safe:
            if cf:
                fp += 1
                outcome = "FP"
            else:
                tn += 1
                outcome = "TN"
        else:
            expected = expected_classes(c)
            has_match = any(category_of(f) in expected for f in cf)
            if has_match:
                tp += 1
                outcome = "TP"
            elif cf:
                # findings exist but wrong class -> FP per Amendment 24
                fp += 1
                outcome = "FP"
            else:
                fn += 1
                outcome = "FN"
        per_case.append({
            "path": c["path"],
            "safe": is_safe,
            "expected": sorted(expected_classes(c)) if not is_safe else [],
            "findings": len(cf),
            "outcome": outcome,
            "aborted": False,
        })

    for i, c in enumerate(cases):
        k = str(c["path"]) + "|" + str(c["method"]) + "|" + str(c["param"])
        ec = exit_codes.get(k, {})
        if not ec.get("aborted"):
            continue
        if per_case[i]["findings"] > 0:
            continue
        if per_case[i]["safe"] and per_case[i]["outcome"] == "TN":
            tn -= 1
            aborts += 1
            per_case[i]["outcome"] = "abort"
            per_case[i]["aborted"] = True
        elif not per_case[i]["safe"] and per_case[i]["outcome"] == "FN":
            aborts += 1
            per_case[i]["aborted"] = True

    P = tp / (tp + fp) if (tp + fp) else 0.0
    R = tp / (tp + fn) if (tp + fn) else 0.0
    F1 = 2 * P * R / (P + R) if (P + R) else 0.0
    fp_rate_safe = fp / (fp + tn) if (fp + tn) else None

    out = {
        "app": args.app,
        "run": str(run_dir),
        "cases": len(cases),
        "vuln_cases": tp + fn,
        "safe_cases": fp + tn,
        "findings": len(findings),
        "unmatched_findings": unmatched_findings,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn, "aborts": aborts,
        "precision": round(P, 4),
        "recall": round(R, 4),
        "f1": round(F1, 4),
        "fp_rate_safe": round(fp_rate_safe, 4) if fp_rate_safe is not None else None,
        "per_case": per_case,
    }
    (run_dir / "score.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    summary = {k: out[k] for k in (
        "app", "cases", "vuln_cases", "safe_cases", "findings",
        "unmatched_findings", "tp", "fp", "fn", "tn", "aborts",
        "precision", "recall", "f1", "fp_rate_safe",
    )}
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
