import argparse
import collections
import csv
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

FAMILY_OF = {
    "xss": "xss",
    "sqli": "sqli",
    "weakrand": "weakrand",
    "cmdi": "cmdi",
    "trustbound": "trustbound",
    "traversal": "pathtraver",
    "securecookie": "securecookie",
    "xpathi": "xpathi",
    "ldapi": "ldapi",
    "crypto": "crypto",
    "hash": "hash",
}

EXCLUDE_FILE = Path("benchmark/track_a/dast_excluded.txt")


def load_excluded():
    if not EXCLUDE_FILE.exists():
        return set()
    ex = set()
    for line in EXCLUDE_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ex.add(line)
    return ex


def family(cat):
    return cat.split("-")[0]


def score(run_dir, cases_csv, label="full"):
    with open(cases_csv, encoding="utf-8", newline="") as fh:
        cases = list(csv.DictReader(fh))
    by_path = {c["urlpath"]: c for c in cases}
    excluded = load_excluded()

    correct_on_path = collections.defaultdict(set)
    n_find = n_wrong = n_orphan = 0
    mismatches = collections.Counter()

    findings_path = Path(run_dir) / "findings.jsonl"
    for line in findings_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        n_find += 1
        d = json.loads(line)
        p = urlparse(d["url"]).path
        if p.startswith("/benchmark"):
            p = p[len("/benchmark") :]
        if p not in by_path:
            n_orphan += 1
            continue
        emitted_fam = FAMILY_OF.get(d["class"], d["class"])
        truth_fam = family(by_path[p]["category"])
        if emitted_fam == truth_fam:
            correct_on_path[p].add(truth_fam)
        else:
            n_wrong += 1
            mismatches[f"{d['class']} -> {by_path[p]['category']}"] += 1

    def tally(filter_excluded):
        TP = FP = FN = TN = 0
        per_cat = collections.defaultdict(lambda: {"TP": 0, "FP": 0, "FN": 0, "TN": 0})
        for c in cases:
            cat = c["category"]
            if filter_excluded and cat in excluded:
                continue
            vuln = c["vulnerable"].strip().lower() == "true"
            detected = family(cat) in correct_on_path.get(c["urlpath"], set())
            if vuln and detected:
                TP += 1
                per_cat[cat]["TP"] += 1
            elif vuln and not detected:
                FN += 1
                per_cat[cat]["FN"] += 1
            elif not vuln and detected:
                FP += 1
                per_cat[cat]["FP"] += 1
            else:
                TN += 1
                per_cat[cat]["TN"] += 1
        P = TP / (TP + FP) if TP + FP else 0
        R = TP / (TP + FN) if TP + FN else 0
        F1 = 2 * P * R / (P + R) if P + R else 0
        return TP, FP, FN, TN, P, R, F1, per_cat

    print(f"RUN {run_dir}")
    print(f"findings={n_find} wrong_family={n_wrong} orphan={n_orphan}")
    print(f"excluded categories: {sorted(excluded)}")
    print()

    dast_metrics = None
    for label, filt in [("FULL CORPUS", False), ("DAST-APPLICABLE", True)]:
        TP, FP, FN, TN, P, R, F1, per_cat = tally(filt)
        if filt:
            dast_metrics = (TP, FP, FN, TN, P, R, F1)
        print(f"=== {label} ===")
        print(f"  TP={TP} FP={FP} FN={FN} TN={TN}")
        print(f"  P={P:.3f}  R={R:.3f}  F1={F1:.3f}")
        print()

    # per-category for DAST-applicable only
    _, _, _, _, _, _, _, per_cat = tally(True)
    print("=== Per-category (DAST-applicable, sorted by F1 ascending) ===")
    rows = []
    for cat, d in per_cat.items():
        tp, fp, fn = d["TP"], d["FP"], d["FN"]
        p = tp / (tp + fp) if tp + fp else 0
        r = tp / (tp + fn) if tp + fn else 0
        f1 = 2 * p * r / (p + r) if p + r else 0
        rows.append((cat, f1, p, r, tp, fp, fn))
    rows.sort(key=lambda x: x[1])
    print(
        f"  {'category':<18} {'F1':>6} {'P':>6} {'R':>6} {'TP':>5} {'FP':>5} {'FN':>5}"
    )
    for cat, f1, p, r, tp, fp, fn in rows:
        print(f"  {cat:<18} {f1:>6.3f} {p:>6.3f} {r:>6.3f} {tp:>5} {fp:>5} {fn:>5}")

    return dast_metrics


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Score a JANISSARY DAST run against the OWASP Benchmark."
    )
    ap.add_argument("run_dir", help="Path to the run directory")
    ap.add_argument(
        "--cases-csv",
        default="benchmark/track_a/case_vectors.csv",
        help="Case vectors CSV (default: full 2,258-case corpus)",
    )
    ap.add_argument(
        "--min-f1",
        type=float,
        default=None,
        help="Exit 1 if DAST-applicable F1 < threshold",
    )
    ap.add_argument(
        "--max-fp",
        type=int,
        default=None,
        help="Exit 1 if DAST-applicable FP > threshold",
    )
    args = ap.parse_args()

    dast = score(args.run_dir, args.cases_csv)

    if args.min_f1 is not None or args.max_fp is not None:
        _, FP, _, _, _, _, F1 = dast
        fail = []
        if args.min_f1 is not None and args.min_f1 > F1:
            fail.append(f"F1 {F1:.3f} < --min-f1 {args.min_f1}")
        if args.max_fp is not None and args.max_fp < FP:
            fail.append(f"FP {FP} > --max-fp {args.max_fp}")
        if fail:
            for msg in fail:
                print(f"THRESHOLD FAIL: {msg}")
            sys.exit(1)
        print(f"THRESHOLD PASS: F1={F1:.3f}, FP={FP}")
