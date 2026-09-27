"""Benchmark analyzer for Track A.

Reads run directories produced by benchmark/track_a/runner.py, matches
findings to ground-truth cases, computes per-run and aggregated metrics,
and runs McNemar's test between tool pairs.

Inputs:
    --cases-csv PATH        Ground truth CSV.
    --runs-dir PATH         Directory containing run subdirs.
    --track {a,b}           Which track. Default: a.
    --out PATH              Where to write the analysis JSON.
                            Default: <runs-dir>/analysis.json

What "case fired" means
-----------------------
For each ground-truth case:
    * vulnerable=True  and tool fired  -> TP
    * vulnerable=True  and tool silent -> FN
    * vulnerable=False and tool fired  -> FP
    * vulnerable=False and tool silent -> TN

A tool "fired" on case C if at least one of its findings maps to C's
testname. Duplicate findings on the same case do not change the case's
classification - that is deliberate. Precision at the finding level
would reward a tool for repeating itself.

Metrics (per run)
-----------------
    TP, FP, TN, FN
    precision   = TP / (TP + FP)      [0 if denominator is 0]
    recall      = TP / (TP + FN)
    fpr         = FP / (FP + TN)
    f1          = 2 * P * R / (P + R)
    youden      = recall + specificity - 1
    scan_time_s wall-clock seconds as reported by the runner
    orphans     findings that did not map to any labelled case

Aggregation
-----------
For each tool, metrics are reported as {per_run: [...], mean: {...},
stdev: {...}} over the 3 runs. Stdev uses population stdev (n divisor),
not sample stdev, since the 3 runs are the entire population of interest.

Statistical test
----------------
McNemar's test, continuity-corrected, on the 2x2 table of per-case
outcomes between two tools, pooling all runs. For each case we ask:
    b = cases where tool1 wrong, tool2 right
    c = cases where tool1 right, tool2 wrong
    chi2 = (|b - c| - 1)^2 / (b + c)
Two-sided p from chi2 with 1 degree of freedom. Under b+c < 25 the
exact binomial fallback is used instead. That fallback is documented in
the output under method="exact_binomial".

Stdlib only. Chi-square df=1 survival uses math.erfc; the exact binomial
two-sided p-value uses math.lgamma.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from benchmark.common.ground_truth import (  # noqa: E402
    Label,
    load_labels,
    testname_from_url,
)
from benchmark.common.run_utils import load_jsonl  # noqa: E402

TOOLS = ("janissary", "zap", "nuclei")


# ---------------------------------------------------------------------
# run loading
# ---------------------------------------------------------------------


def load_run(run_dir: Path, labels: dict[str, Label]) -> dict:
    """Return the per-case classification for one run directory."""
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"missing manifest: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    tool = manifest["tool"]

    findings = load_jsonl(run_dir / "findings.jsonl")
    fired_cases: set[str] = set()
    orphans = 0
    for f in findings:
        url = f.get("url") or f.get("matched-at") or f.get("matched_at") or ""
        name = testname_from_url(url)
        if name is None or name not in labels:
            orphans += 1
            continue
        fired_cases.add(name)

    per_case: dict[str, str] = {}
    for name, case in labels.items():
        if case.vulnerable and name in fired_cases:
            per_case[name] = "TP"
        elif case.vulnerable and name not in fired_cases:
            per_case[name] = "FN"
        elif not case.vulnerable and name in fired_cases:
            per_case[name] = "FP"
        else:
            per_case[name] = "TN"

    return {
        "run_dir": str(run_dir),
        "tool": tool,
        "run_number": manifest.get("run_number"),
        "tool_version": manifest.get("tool_version"),
        "findings_total": len(findings),
        "orphans": orphans,
        "fired_cases": sorted(fired_cases),
        "per_case": per_case,
        "scan_time_s": read_elapsed(run_dir),
        "manifest": manifest,
    }


def read_elapsed(run_dir: Path) -> float | None:
    p = run_dir / "elapsed.txt"
    if not p.exists():
        return None
    try:
        return float(p.read_text(encoding="utf-8").strip())
    except ValueError:
        return None


def discover_runs(runs_dir: Path) -> list[Path]:
    if not runs_dir.exists():
        return []
    out: list[Path] = []
    for entry in sorted(runs_dir.iterdir()):
        if entry.is_dir() and (entry / "manifest.json").exists():
            out.append(entry)
    return out


# ---------------------------------------------------------------------
# metrics
# ---------------------------------------------------------------------


def confusion(per_case: dict[str, str]) -> dict[str, int]:
    c = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    for v in per_case.values():
        c[v] = c.get(v, 0) + 1
    return c


def metrics_from_confusion(c: dict[str, int]) -> dict[str, float]:
    tp, fp, tn, fn = c["TP"], c["FP"], c["TN"], c["FN"]
    denom_p = tp + fp
    denom_r = tp + fn
    denom_fpr = fp + tn
    precision = tp / denom_p if denom_p else 0.0
    recall = tp / denom_r if denom_r else 0.0
    fpr = fp / denom_fpr if denom_fpr else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    specificity = 1.0 - fpr
    youden = recall + specificity - 1.0
    return {
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "fpr": round(fpr, 6),
        "f1": round(f1, 6),
        "youden": round(youden, 6),
    }


def summarize_tool(runs: list[dict]) -> dict:
    if not runs:
        return {"per_run": [], "mean": {}, "stdev": {}}
    per_run = []
    for r in runs:
        c = confusion(r["per_case"])
        m = metrics_from_confusion(c)
        row = {
            "run_dir": r["run_dir"],
            "run_number": r["run_number"],
            "tool_version": r["tool_version"],
            "confusion": c,
            "metrics": m,
            "findings_total": r["findings_total"],
            "orphans": r["orphans"],
            "scan_time_s": r["scan_time_s"],
        }
        per_run.append(row)

    def agg(key: str) -> dict[str, float]:
        vals = [row["metrics"][key] for row in per_run]
        return {"mean": round(mean(vals), 6), "stdev": round(pstdev(vals), 6)}

    agg_keys = ["precision", "recall", "fpr", "f1", "youden"]
    times = [row["scan_time_s"] for row in per_run if row["scan_time_s"] is not None]
    time_stats = {"mean": round(mean(times), 3), "stdev": round(pstdev(times), 3)} if times else {}

    return {
        "per_run": per_run,
        "mean": {k: agg(k)["mean"] for k in agg_keys},
        "stdev": {k: agg(k)["stdev"] for k in agg_keys},
        "scan_time_s": time_stats,
    }


# ---------------------------------------------------------------------
# McNemar
# ---------------------------------------------------------------------


def mcnemar(a: dict[str, str], b: dict[str, str]) -> dict:
    """Compare two tools' per-case outcomes.

    Correct/incorrect is defined per case as:
        correct = the tool's classification matches the ground truth label
                  for that case.
    That is:
        TP or TN -> correct
        FP or FN -> incorrect
    """
    common = sorted(set(a) & set(b))
    if not common:
        return {"n": 0, "b": 0, "c": 0, "chi2": None, "p": None, "method": "none"}

    def correct(v: str) -> bool:
        return v in ("TP", "TN")

    bb = cc = 0
    for name in common:
        ok_a = correct(a[name])
        ok_b = correct(b[name])
        if not ok_a and ok_b:
            bb += 1
        elif ok_a and not ok_b:
            cc += 1

    if bb + cc < 25:
        p = _exact_binomial_two_sided(bb, bb + cc)
        return {
            "n": len(common),
            "b": bb,
            "c": cc,
            "chi2": None,
            "p": round(p, 6),
            "method": "exact_binomial",
            "significant_0_05": p < 0.05,
        }

    chi2 = (abs(bb - cc) - 1) ** 2 / (bb + cc)
    p = _chi2_df1_sf(chi2)
    return {
        "n": len(common),
        "b": bb,
        "c": cc,
        "chi2": round(chi2, 6),
        "p": round(p, 6),
        "method": "chi2_continuity_corrected",
        "significant_0_05": p < 0.05,
    }
    return {
        "n": len(common),
        "b": bb,
        "c": cc,
        "chi2": round(chi2, 6),
        "p": round(p, 6),
        "method": "chi2_continuity_corrected",
        "significant_0_05": p < 0.05,
    }




def _chi2_df1_sf(x: float) -> float:
    """Survival function P(X > x) for chi-square with 1 degree of freedom.

    For df=1: 1 - CDF(x) = erfc(sqrt(x/2)).
    Stdlib-only; matches scipy.stats.chi2.sf(x, 1) to machine precision.
    """
    import math

    if x <= 0:
        return 1.0
    return math.erfc(math.sqrt(x / 2.0))


def _exact_binomial_two_sided(k: int, n: int) -> float:
    """Two-sided exact binomial p-value for H0: p=0.5.

    Returns the sum of P(X=i) for all i with P(X=i) <= P(X=k), where
    X ~ Binomial(n, 0.5). This is the standard "method of small p-values"
    and matches scipy.stats.binomtest(..., alternative="two-sided").
    """
    import math

    if n == 0:
        return 1.0

    def log_pmf(i: int) -> float:
        return (
            math.lgamma(n + 1)
            - math.lgamma(i + 1)
            - math.lgamma(n - i + 1)
            - n * math.log(2)
        )

    log_pk = log_pmf(k)
    tol = 1e-12
    p = 0.0
    for i in range(n + 1):
        lp = log_pmf(i)
        if lp <= log_pk + tol:
            p += math.exp(lp)
    return min(1.0, p)
# ---------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="benchmark.analyze",
        description="Analyze benchmark runs (see BENCHMARK.md).",
    )
    p.add_argument("--cases-csv", type=Path, required=True)
    p.add_argument("--runs-dir", type=Path, required=True)
    p.add_argument("--out", type=Path, default=None)
    args = p.parse_args(argv)

    labels = load_labels(args.cases_csv)
    runs = discover_runs(args.runs_dir)
    if not runs:
        print(f"[analyze] no runs found in {args.runs_dir}", file=sys.stderr)
        return 2

    by_tool: dict[str, list[dict]] = defaultdict(list)
    for run_dir in runs:
        try:
            row = load_run(run_dir, labels)
        except FileNotFoundError as exc:
            print(f"[analyze] skipping {run_dir}: {exc}", file=sys.stderr)
            continue
        by_tool[row["tool"]].append(row)

    # Stable ordering: by run_number within each tool.
    for t in by_tool:
        by_tool[t].sort(key=lambda r: r["run_number"] or 0)

    summary: dict[str, Any] = {
        "schema_version": "1.0",
        "cases_csv": str(args.cases_csv),
        "runs_dir": str(args.runs_dir),
        "case_count": len(labels),
        "tools": {},
    }
    for tool in TOOLS:
        if tool in by_tool:
            summary["tools"][tool] = summarize_tool(by_tool[tool])

    # McNemar: pool per-case outcomes across runs per tool.
    def pooled(tool: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for r in by_tool.get(tool, []):
            for name, v in r["per_case"].items():
                prev = out.get(name)
                # If a case was TP in one run and FN in another, we
                # conservatively record it as TP (the tool *can* find it).
                # If FP in one run and TN in another, we record FP.
                # Deterministic, documented, applied equally to all tools.
                if prev is None:
                    out[name] = v
                else:
                    out[name] = merge_outcomes(prev, v)
        return out

    stats: dict[str, dict] = {}
    for i, t1 in enumerate(TOOLS):
        for t2 in TOOLS[i + 1:]:
            if t1 in by_tool and t2 in by_tool:
                stats[f"{t1}_vs_{t2}"] = mcnemar(pooled(t1), pooled(t2))
    summary["mcnemar"] = stats

    out_path = args.out or (args.runs_dir / "analysis.json")
    out_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(f"[analyze] wrote {out_path}")
    print(f"[analyze] tools: {sorted(summary['tools'])}")
    print(f"[analyze] mcnemar: {sorted(summary['mcnemar'])}")
    return 0


def merge_outcomes(a: str, b: str) -> str:
    """Merge a case's outcome across runs.

    Priority order (most-signal wins):
        TP > FP > FN > TN
    Rationale: a tool that fires on a vulnerable case in ANY run has
    demonstrably detected that bug; we do not want run-to-run noise to
    hide that. Same logic for FP - firing on a safe case once is still a
    false positive even if the tool was silent on a different run.
    """
    order = {"TP": 0, "FP": 1, "FN": 2, "TN": 3}
    return a if order.get(a, 99) <= order.get(b, 99) else b


if __name__ == "__main__":
    sys.exit(main())
