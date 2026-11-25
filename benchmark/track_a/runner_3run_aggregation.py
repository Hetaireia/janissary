"""Three-run aggregation for Janissary on Track A (ADR-036 phase 6).

Scoring is delegated to score_dast_aware.score() so an aggregate cannot
drift from the published metric. A separate per-case pass reproduces that
matrix and is asserted equal to the tuple score() returns before any gate
runs, so a gate can never read a different rule set.

Report shape mirrors benchmark/analyze.py: a per_run list plus mean and
population stdev, stdev taken over the runs because they are the whole
population of interest.

Usage
    python -m benchmark.track_a.runner_3run_aggregation --run DIR --run DIR \
        --run DIR --baseline-runs DIR DIR DIR \
        --cases-csv benchmark/track_a/case_vectors.csv --floor 0.323

Exit codes
    0   every requested gate passed
    1   a gate failed
    2   bad invocation or unusable run directory
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import io
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, pstdev
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from benchmark.common.run_utils import load_jsonl  # noqa: E402
from benchmark.track_a import score_dast_aware  # noqa: E402

TARGET_FAMILY = "pathtraver"

EXIT_OK = 0
EXIT_GATE = 1
EXIT_USAGE = 2


class UsageError(Exception):
    """Unusable invocation, run directory or corpus."""


def read_cases(cases_csv: Path) -> list[dict]:
    with Path(cases_csv).open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        raise UsageError(f"no cases in {cases_csv}")
    for need in ("testname", "urlpath", "category", "vulnerable"):
        if need not in rows[0]:
            raise UsageError(f"{cases_csv}: missing column {need}")
    return rows


def read_manifest(run_dir: Path) -> dict:
    path = Path(run_dir) / "manifest.json"
    if not path.exists():
        raise UsageError(f"missing manifest: {path}")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise UsageError(f"{path}: {exc}") from exc
    tool = doc.get("tool")
    if tool != "janissary":
        raise UsageError(f"{run_dir}: tool {tool!s} is not janissary")
    return doc


def _published(run_dir: Path, cases_csv: Path) -> tuple:
    """Call the authoritative scorer, tolerating its older signature."""
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            return score_dast_aware.score(str(run_dir), str(cases_csv))
        except TypeError:
            return score_dast_aware.score(str(run_dir))


def classify(run_dir: Path, cases: list[dict], excluded: set[str]) -> list[dict]:
    """Return one outcome row per case, mirroring score_dast_aware.score().

    Same steps in the same order: strip the /benchmark prefix, drop orphans,
    drop out-of-scope classes, map the finding class through FAMILY_OF, and
    mark a case detected however many findings it drew.
    """
    by_path = {c["urlpath"]: c for c in cases}
    seen: dict[str, set[str]] = defaultdict(set)
    for finding in load_jsonl(Path(run_dir) / "findings.jsonl"):
        path = urlparse(finding.get("url") or "").path
        if path.startswith("/benchmark"):
            path = path[len("/benchmark") :]
        if path not in by_path:
            continue
        cls = finding.get("class") or ""
        if cls in score_dast_aware.OUT_OF_SCOPE_CLASSES:
            continue
        seen[path].add(score_dast_aware.FAMILY_OF.get(cls, cls))
    rows = []
    for case in cases:
        cat = case["category"]
        truth = score_dast_aware.family(cat)
        rows.append(
            {
                "urlpath": case["urlpath"],
                "category": cat,
                "family": truth,
                "vulnerable": case["vulnerable"].strip().lower() == "true",
                "excluded": cat in excluded,
                "detected": truth in seen.get(case["urlpath"], set()),
            }
        )
    return rows


def confusion(rows: list[dict]) -> tuple[int, int, int, int]:
    tp = fp = fn = tn = 0
    for row in rows:
        if row["excluded"]:
            continue
        if row["vulnerable"]:
            if row["detected"]:
                tp += 1
            else:
                fn += 1
        elif row["detected"]:
            fp += 1
        else:
            tn += 1
    return tp, fp, fn, tn


def ratios(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    denom = precision + recall
    f1 = (2 * precision * recall / denom) if denom else 0.0
    return precision, recall, f1


def family_recall(rows: list[dict], family_name: str) -> tuple[float, int, int]:
    tp = fn = 0
    for row in rows:
        if row["excluded"] or not row["vulnerable"]:
            continue
        if row["family"] != family_name:
            continue
        if row["detected"]:
            tp += 1
        else:
            fn += 1
    recall = tp / (tp + fn) if tp + fn else 0.0
    return recall, tp, fn


def true_positives(rows: list[dict]) -> set[str]:
    return {
        r["urlpath"]
        for r in rows
        if r["vulnerable"] and r["detected"] and not r["excluded"]
    }


def verified_rows(
    run_dir: Path,
    cases: list[dict],
    cases_csv: Path,
    excluded: set[str] | None = None,
) -> list[dict]:
    """Classify one run, proving the tally agrees with score() first."""
    if excluded is None:
        excluded = score_dast_aware.load_excluded()
    rows = classify(run_dir, cases, excluded)
    got = confusion(rows)
    published = _published(run_dir, cases_csv)
    if published is None:
        raise UsageError(f"{run_dir}: scorer produced no DAST tuple")
    want = tuple(published[:4])
    if got != want:
        raise UsageError(
            f"{run_dir}: per-case tally {got} != scorer {want}; a gate would "
            "use a rule set other than the published metric"
        )
    return rows


def score_run(
    run_dir: Path,
    cases: list[dict],
    cases_csv: Path,
    excluded: set[str],
) -> tuple[dict, list[dict]]:
    manifest = read_manifest(run_dir)
    rows = verified_rows(run_dir, cases, cases_csv, excluded)
    tp, fp, fn, tn = confusion(rows)
    precision, recall, f1 = ratios(tp, fp, fn)
    target_recall, target_tp, target_fn = family_recall(rows, TARGET_FAMILY)
    row = {
        "run_dir": str(run_dir),
        "run_number": manifest.get("run_number"),
        "tool_version": manifest.get("tool_version"),
        "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "metrics": {
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
        },
        "target_recall": round(target_recall, 6),
        "target_tp": target_tp,
        "target_fn": target_fn,
    }
    return row, rows


def aggregate(per_run: list[dict]) -> dict:
    out = {"mean": {}, "stdev": {}}
    for key in ("precision", "recall", "f1", "target_recall"):
        vals = [
            row["metrics"][key] if key in row["metrics"] else row[key]
            for row in per_run
        ]
        out["mean"][key] = round(mean(vals), 6) if vals else 0.0
        out["stdev"][key] = round(pstdev(vals), 6) if len(vals) > 1 else 0.0
    return out


def false_positives(rows: list[dict]) -> list[dict]:
    return [
        {"urlpath": r["urlpath"], "category": r["category"]}
        for r in rows
        if not r["vulnerable"] and r["detected"]
    ]


def default_out(first_run: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path(first_run).resolve().parent / f"{stamp}-aggregation.json"


def report(summary: dict) -> None:
    header = f"{'run':<26} {'run#':>4} {'target R':>9} {'P':>7} {'R':>7} {'F1':>7}"
    print(header)
    for row in summary["runs"]:
        name = Path(row["run_dir"]).name
        metrics = row["metrics"]
        print(
            f"{name:<26} {row['run_number']!s:>4} "
            f"{row['target_recall']:>9.3f} {metrics['precision']:>7.3f} "
            f"{metrics['recall']:>7.3f} {metrics['f1']:>7.3f}"
        )
    for label in ("mean", "stdev"):
        block = summary["aggregate"][label]
        print(
            f"{label:<26} {'':>4} {block['target_recall']:>9.3f} "
            f"{block['precision']:>7.3f} {block['recall']:>7.3f} "
            f"{block['f1']:>7.3f}"
        )
    for name in sorted(summary["gates"]):
        gate = summary["gates"][name]
        verdict = "PASS" if gate.get("passed") else "FAIL"
        print(f"[gate] {name}: {verdict} {json.dumps(gate, sort_keys=True)}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="benchmark.track_a.runner_3run_aggregation",
        description="Aggregate and gate Track A runs (ADR-036 phase 6).",
    )
    p.add_argument(
        "--run",
        action="append",
        required=True,
        type=Path,
        metavar="DIR",
        help="Run directory; repeat once per run.",
    )
    p.add_argument("--cases-csv", required=True, type=Path)
    p.add_argument(
        "--baseline-runs",
        nargs="+",
        type=Path,
        default=None,
        metavar="DIR",
        help="Runs whose true positives must survive.",
    )
    p.add_argument("--floor", type=float, default=None)
    p.add_argument("--max-fp", type=int, default=None)
    p.add_argument("--negative-runs", nargs="+", type=Path, default=None)
    p.add_argument("--negative-cases", type=Path, default=None)
    p.add_argument("--out", type=Path, default=None)
    p.add_argument(
        "--allow-partial",
        action="store_true",
        help="Accept fewer than three runs.",
    )
    return p


def run(args) -> int:
    if args.negative_runs and not args.negative_cases:
        raise UsageError("--negative-runs needs --negative-cases")
    if args.negative_cases and not args.negative_runs:
        raise UsageError("--negative-cases needs --negative-runs")
    if len(args.run) > 3:
        raise UsageError(f"at most three --run, got {len(args.run)}")
    if len(args.run) < 3 and not args.allow_partial:
        raise UsageError("three --run required (or --allow-partial)")
    numbers = [read_manifest(d).get("run_number") for d in args.run]
    if len(set(numbers)) != len(numbers):
        raise UsageError(f"duplicate run numbers: {numbers}")

    cases = read_cases(args.cases_csv)
    excluded = score_dast_aware.load_excluded()
    per_run = []
    tp_sets = []
    for run_dir in args.run:
        row, rows = score_run(run_dir, cases, args.cases_csv, excluded)
        per_run.append(row)
        tp_sets.append(true_positives(rows))

    summary: dict = {
        "cases_csv": str(args.cases_csv),
        "runs": per_run,
        "aggregate": aggregate(per_run),
        "gates": {},
        "failed": False,
    }

    if args.baseline_runs:
        baseline_tp: set[str] = set()
        for base in args.baseline_runs:
            baseline_tp |= true_positives(classify(base, cases, excluded))
        held = {p: sum(1 for s in tp_sets if p in s) for p in baseline_tp}
        regressed = sorted(p for p, n in held.items() if n == 0)
        fragile = sorted(p for p, n in held.items() if 0 < n < len(tp_sets))
        gate = {
            "baseline_true_positives": len(baseline_tp),
            "held": sum(1 for n in held.values() if n > 0),
            "regressed": regressed,
            "fragile": fragile,
            "passed": not regressed,
        }
        summary["gates"]["baseline"] = gate
        if regressed:
            summary["failed"] = True

    if args.floor is not None:
        got = summary["aggregate"]["mean"]["target_recall"]
        gate = {
            "target_family": TARGET_FAMILY,
            "floor": args.floor,
            "mean_recall": got,
            "passed": got >= args.floor,
        }
        summary["gates"]["floor"] = gate
        if not gate["passed"]:
            summary["failed"] = True

    if args.max_fp is not None:
        total = sum(r["confusion"]["fp"] for r in per_run)
        gate = {
            "limit": args.max_fp,
            "false_positives": total,
            "passed": total <= args.max_fp,
        }
        summary["gates"]["max_fp"] = gate
        if not gate["passed"]:
            summary["failed"] = True

    if args.negative_runs:
        neg_cases = read_cases(args.negative_cases)
        found = []
        for run_dir in args.negative_runs:
            for fp in false_positives(classify(run_dir, neg_cases, set())):
                found.append({"run_dir": str(run_dir), **fp})
        gate = {
            "cases": len(neg_cases),
            "runs": len(args.negative_runs),
            "false_positives": found,
            "passed": not found,
        }
        summary["gates"]["negative"] = gate
        if found:
            summary["failed"] = True

    out = args.out or default_out(args.run[0])
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    report(summary)
    print(f"[aggregation] wrote {out}")
    return EXIT_GATE if summary["failed"] else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except UsageError as exc:
        print(f"[aggregation] {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
