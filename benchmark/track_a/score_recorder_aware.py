"""score_recorder_aware.py — recorder-aware diagnostic for a Track A run.

Informational only: reconciles scorer findings, recorder observations, and
the runner's primary per-case recording dispositions. It does not score or
modify a benchmark run.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlparse

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
try:
    from score_dast_aware import FAMILY_OF, OUT_OF_SCOPE_CLASSES, family
except ImportError as exc:
    raise SystemExit(
        f"score_recorder_aware: cannot import from score_dast_aware: {exc}"
    ) from exc


def _load_jsonl(path: Path) -> tuple[list[dict], list[dict]]:
    """Return valid object rows and explicit diagnostics for malformed rows."""
    rows: list[dict] = []
    malformed: list[dict] = []
    if not path.exists():
        return rows, malformed
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return rows, [
            {"source": path.name, "kind": "file_read_error", "error": str(exc)}
        ]
    for line_number, raw in enumerate(lines, 1):
        value = raw.strip()
        if not value:
            continue
        try:
            item = json.loads(value)
        except json.JSONDecodeError as exc:
            malformed.append(
                {
                    "source": path.name,
                    "line": line_number,
                    "kind": "malformed_jsonl",
                    "error": str(exc),
                    "raw": value,
                }
            )
            continue
        if not isinstance(item, dict):
            malformed.append(
                {
                    "source": path.name,
                    "line": line_number,
                    "kind": "jsonl_row_not_object",
                    "value": item,
                }
            )
            continue
        rows.append(item)
    return rows, malformed


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"{path} must contain a JSON object")
    return value


def _load_cases(path: Path) -> dict[str, dict]:
    with path.open(encoding="utf-8", newline="") as fh:
        return {r["testname"]: r for r in csv.DictReader(fh) if r.get("testname")}


def _finding_path(finding: dict) -> str | None:
    url = finding.get("url")
    if not isinstance(url, str):
        return None
    path = urlparse(url).path
    if path.startswith("/benchmark"):
        path = path[len("/benchmark") :]
    return path


def _resolve_cases_csv(run_dir: Path, override: Path | None) -> Path:
    if override is not None:
        if override.exists():
            return override
        raise SystemExit(f"cases_csv override not found: {override}")
    manifest = _load_json(run_dir / "manifest.json")
    raw = manifest.get("cases_csv")
    if not raw:
        raise SystemExit(
            "manifest.cases_csv missing and no --cases-csv override supplied"
        )
    path = Path(raw)
    if path.is_absolute() and path.exists():
        return path
    if path.exists():
        return path
    for up in range(1, 6):
        try:
            candidate = run_dir.parents[up] / raw
        except IndexError:
            break
        if candidate.exists():
            return candidate
    raise SystemExit(f"cases_csv {raw!r} not resolvable from cwd or run_dir parents")


def _classify_finding(finding: dict, case: dict | None) -> dict:
    cls = finding.get("class", "")
    result = {
        "class": cls,
        "emitted_family": FAMILY_OF.get(cls, cls),
        "effective": False,
        "reason": None,
    }
    if case is None:
        result["reason"] = "orphan"
    elif cls in OUT_OF_SCOPE_CLASSES:
        result["reason"] = "out_of_scope"
    elif result["emitted_family"] == family(case["category"]):
        result["effective"] = True
        result["reason"] = "scored"
    else:
        result["reason"] = "family_mismatch"
    return result


def _diagnostic_band(*, cls: str, fired: bool, eff: bool, ind: bool) -> str:
    if ind:
        return "recorder_indeterminate"
    if cls == "no_observable_divergence":
        return "scorer_finding_no_recorder" if eff else "agree_clean"
    if cls == "inconclusive":
        return "recorder_inconclusive"
    if fired:
        return "agree_detected" if eff else "recorder_signal_no_finding"
    if eff:
        return "scorer_finding_no_recorder"
    return "unrecognised_classification"


def _case_ids_from_selection(selection: dict) -> set[str]:
    return {str(cid) for cid in selection if str(cid)}


def _disposition_rows(rows_by_name: dict[str, list[dict]], cid: str) -> list[str]:
    return [
        name
        for name, rows in rows_by_name.items()
        if any(
            str(row.get("case_id") or row.get("testname") or "") == cid for row in rows
        )
    ]


def diagnose(run_dir, cases_csv=None) -> dict:
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise SystemExit(f"run dir not found: {run_dir}")

    resolved_csv = _resolve_cases_csv(run_dir, Path(cases_csv) if cases_csv else None)
    cases = _load_cases(resolved_csv)
    selection = _load_json(run_dir / "case_selection.json")
    summary = _load_json(run_dir / "recording_summary.json")
    status = _load_json(run_dir / "recording_status.json")

    if "recording_enabled" in status:
        recording_enabled = bool(status["recording_enabled"])
        recording_enabled_source = "recording_status.json"
    elif "recording_enabled" in summary:
        recording_enabled = bool(summary["recording_enabled"])
        recording_enabled_source = "recording_summary.json"
    else:
        recording_enabled = None
        recording_enabled_source = None

    anomalies: list[dict] = []
    if recording_enabled is None:
        anomalies.append({"kind": "recording_enabled_status_unknown"})
    if recording_enabled is True:
        if not selection:
            anomalies.append({"kind": "recording_enabled_selection_missing_or_empty"})
        universe = _case_ids_from_selection(selection)
    elif recording_enabled is False:
        universe = set(cases)
    else:
        # Without a trustworthy recording mode, avoid treating raw output as
        # proof that a case was selected. Use selection if present, otherwise
        # the corpus as a provisional universe and disclose the uncertainty.
        universe = _case_ids_from_selection(selection) or set(cases)

    if recording_enabled is True:
        for cid in sorted(universe - set(cases)):
            anomalies.append(
                {
                    "kind": "selected_case_missing_from_corpus",
                    "case_id": cid,
                }
            )

    filenames = {
        "indeterminate": "case_recording_indeterminate.jsonl",
        "zero_observations": "case_zero_observations.jsonl",
        "recording_failed": "case_recording_failed.jsonl",
        "missing": "case_missing.jsonl",
    }
    loaded: dict[str, list[dict]] = {}
    malformed: list[dict] = []
    for key, filename in filenames.items():
        loaded[key], errors = _load_jsonl(run_dir / filename)
        malformed.extend(errors)
    cr, errors = _load_jsonl(run_dir / "case_records.jsonl")
    malformed.extend(errors)
    findings, errors = _load_jsonl(run_dir / "findings.jsonl")
    malformed.extend(errors)
    anomalies.extend(malformed)

    rows_by_name = {name: loaded[name] for name in filenames}
    disposition_by_case: dict[str, list[str]] = defaultdict(list)
    for name, rows in rows_by_name.items():
        seen: set[str] = set()
        for row in rows:
            cid = str(row.get("case_id") or row.get("testname") or "")
            if not cid:
                anomalies.append(
                    {
                        "kind": "disposition_row_missing_case_id",
                        "source": filenames[name],
                        "row": row,
                    }
                )
                continue
            if cid in seen:
                anomalies.append(
                    {
                        "kind": "duplicate_disposition_row",
                        "case_id": cid,
                        "disposition": name,
                        "source": filenames[name],
                    }
                )
            seen.add(cid)
            disposition_by_case[cid].append(
                "recording_indeterminate" if name == "indeterminate" else name
            )

    obs_by: dict[str, list[dict]] = defaultdict(list)
    unmatched_observations: list[dict] = []
    for row in cr:
        cid = str(row.get("case_id") or "")
        if not cid:
            anomalies.append({"kind": "observation_row_missing_case_id", "row": row})
        elif row.get("enriched") is False or cid not in universe:
            unmatched_observations.append(row)
        else:
            obs_by[cid].append(row)

    paths = {c["urlpath"] for c in cases.values()}
    by_path: dict[str, list[dict]] = defaultdict(list)
    orphan: list[dict] = []
    unselected_findings: list[dict] = []
    for finding in findings:
        path = _finding_path(finding)
        if path is None:
            orphan.append({**finding, "_reason": "unparsable_url"})
            continue
        if path not in paths:
            orphan.append(
                {
                    **finding,
                    "_path": path,
                    "_reason": "path_not_in_corpus",
                }
            )
            continue
        matching_ids = [
            cid for cid, case in cases.items() if case.get("urlpath") == path
        ]
        selected_matches = [cid for cid in matching_ids if cid in universe]
        if not selected_matches:
            unselected_findings.append(
                {
                    **finding,
                    "_path": path,
                    "_reason": "finding_for_unselected_case",
                }
            )
        else:
            by_path[path].append(finding)

    case_raw = run_dir / "case_raw"
    raw_case_dirs = (
        {p.name for p in case_raw.iterdir() if p.is_dir()}
        if case_raw.is_dir()
        else set()
    )
    unmatched_raw_cases = sorted(raw_case_dirs - universe)
    for cid in unmatched_raw_cases:
        anomalies.append({"kind": "raw_case_outside_run_selection", "case_id": cid})

    per_case: list[dict] = []
    bands: Counter[str] = Counter()
    observed_dispositions: Counter[str] = Counter()

    for cid in sorted(universe):
        case = cases.get(cid)
        category = case.get("category") if case else None
        vulnerable = (case or {}).get("vulnerable", "").strip().lower() == "true"
        urlpath = case.get("urlpath") if case else None

        raw_file = case_raw / cid / "case_records_raw.jsonl"
        raw_present = False
        if raw_file.exists():
            try:
                raw_present = any(
                    line.strip()
                    for line in raw_file.read_text(encoding="utf-8").splitlines()
                )
            except OSError as exc:
                anomalies.append(
                    {
                        "kind": "raw_evidence_read_error",
                        "case_id": cid,
                        "error": str(exc),
                    }
                )

        disposition_names = disposition_by_case.get(cid, [])
        distinct_dispositions = sorted(set(disposition_names))
        if len(distinct_dispositions) > 1:
            primary = "conflict"
            anomalies.append(
                {
                    "kind": "primary_disposition_conflict",
                    "case_id": cid,
                    "dispositions": distinct_dispositions,
                }
            )
        elif distinct_dispositions:
            primary = distinct_dispositions[0]
        elif recording_enabled is False:
            primary = (
                "missing" if "missing" in disposition_names else "recording_disabled"
            )
        elif obs_by.get(cid):
            primary = "has_observations"
        else:
            primary = "unclassified"
            anomalies.append(
                {
                    "case_id": cid,
                    "kind": (
                        "raw_present_but_no_case_records"
                        if raw_present
                        else "no_records_not_indeterminate"
                    ),
                }
            )

        observed_dispositions[primary] += 1
        ind_rows = [
            row
            for row in loaded["indeterminate"]
            if str(row.get("case_id") or row.get("testname") or "") == cid
        ]
        ind_reason = ind_rows[0].get("reason") if ind_rows else None
        obs = obs_by.get(cid, [])
        case_findings = by_path.get(urlpath, []) if urlpath else []
        classified_findings = [
            _classify_finding(finding, case) for finding in case_findings
        ]
        effective = any(item["effective"] for item in classified_findings)

        observations: list[dict] = []
        if obs:
            for row in obs:
                band = _diagnostic_band(
                    cls=row.get("classification") or "",
                    fired=bool(row.get("oracle_fired")),
                    eff=effective,
                    ind=False,
                )
                observations.append(
                    {
                        "observation_id": row.get("observation_id"),
                        "classification": row.get("classification"),
                        "oracle_fired": bool(row.get("oracle_fired")),
                        "diagnostic_band": band,
                    }
                )
                bands[band] += 1
        if primary == "recording_indeterminate":
            observations.append(
                {
                    "observation_id": None,
                    "classification": None,
                    "oracle_fired": None,
                    "diagnostic_band": "recorder_indeterminate",
                    "indeterminate_reason": ind_reason,
                }
            )
            bands["recorder_indeterminate"] += 1
        elif primary == "recording_failed":
            observations.append(
                {
                    "observation_id": None,
                    "classification": None,
                    "oracle_fired": None,
                    "diagnostic_band": "recording_failed",
                }
            )
            bands["recording_failed"] += 1
        elif primary == "zero_observations":
            observations.append(
                {
                    "observation_id": None,
                    "classification": None,
                    "oracle_fired": None,
                    "diagnostic_band": "zero_observations",
                }
            )
            bands["zero_observations"] += 1
        elif primary == "missing":
            observations.append(
                {
                    "observation_id": None,
                    "classification": None,
                    "oracle_fired": None,
                    "diagnostic_band": "recording_missing",
                }
            )
            bands["recording_missing"] += 1
        elif primary == "recording_disabled":
            observations.append(
                {
                    "observation_id": None,
                    "classification": None,
                    "oracle_fired": None,
                    "diagnostic_band": "recording_disabled",
                }
            )
            bands["recording_disabled"] += 1
        elif not obs:
            band = (
                "recording_anomaly_raw_no_records"
                if raw_present
                else "recording_anomaly"
            )
            observations.append(
                {
                    "observation_id": None,
                    "classification": None,
                    "oracle_fired": None,
                    "diagnostic_band": band,
                }
            )
            bands[band] += 1

        per_case.append(
            {
                "case_id": cid,
                "benchmark_category": category,
                "urlpath": urlpath,
                "vulnerable": vulnerable,
                "primary_disposition": primary,
                "raw_evidence_present": raw_present,
                "indeterminate_reason": ind_reason,
                "raw_findings": classified_findings,
                "effective_scored": effective,
                "observations": observations,
            }
        )

    claimed_sum = summary.get("primary_dispositions_sum")
    total = len(universe)
    summary_counts = summary.get("primary_dispositions")
    if not isinstance(summary_counts, dict):
        summary_counts = {}

    accounting = {
        "summary_present": bool(summary),
        "recording_enabled": recording_enabled,
        "recording_enabled_source": recording_enabled_source,
        "cases_total_claimed": summary.get("cases_total"),
        "cases_total_observed": total,
        "primary_dispositions_sum": claimed_sum,
        "primary_dispositions_observed": dict(observed_dispositions),
        "accounting_valid": summary.get("accounting_valid"),
        "indeterminate_file_rows": len(loaded["indeterminate"]),
        "missing_file_rows": len(loaded["missing"]),
        "zero_obs_file_rows": len(loaded["zero_observations"]),
        "failed_file_rows": len(loaded["recording_failed"]),
        "consistent": (claimed_sum == total if isinstance(claimed_sum, int) else None),
    }
    if isinstance(claimed_sum, int) and claimed_sum != total:
        anomalies.append(
            {
                "kind": "accounting_mismatch",
                "claimed": claimed_sum,
                "observed": total,
            }
        )
    cases_claimed = summary.get("cases_total")
    if isinstance(cases_claimed, int) and cases_claimed != total:
        anomalies.append(
            {
                "kind": "cases_total_mismatch",
                "claimed": cases_claimed,
                "observed": total,
            }
        )

    file_for_disposition = {
        "recording_indeterminate": "indeterminate",
        "zero_observations": "zero_observations",
        "recording_failed": "recording_failed",
        "missing": "missing",
    }
    for disposition, file_key in file_for_disposition.items():
        claimed = summary_counts.get(disposition)
        observed = len(loaded[file_key])
        if isinstance(claimed, int) and claimed != observed:
            anomalies.append(
                {
                    "kind": "disposition_count_mismatch",
                    "disposition": disposition,
                    "summary_claims": claimed,
                    "file_rows": observed,
                }
            )

    for disposition, claimed in summary_counts.items():
        if isinstance(claimed, int):
            observed = observed_dispositions.get(disposition, 0)
            if claimed != observed:
                anomalies.append(
                    {
                        "kind": "primary_disposition_summary_mismatch",
                        "disposition": disposition,
                        "summary_claims": claimed,
                        "observed_cases": observed,
                    }
                )

    accounting["unmatched_observation_rows"] = len(unmatched_observations)
    accounting["unselected_finding_rows"] = len(unselected_findings)
    accounting["unmatched_raw_case_dirs"] = len(unmatched_raw_cases)

    return {
        "run_dir": str(run_dir),
        "cases_csv": str(resolved_csv),
        "total_cases": total,
        "per_case": per_case,
        "band_counts": dict(bands),
        "accounting": accounting,
        "orphan_findings": orphan,
        "unselected_findings": unselected_findings,
        "unmatched_observations": unmatched_observations,
        "unmatched_raw_cases": unmatched_raw_cases,
        "anomalies": anomalies,
    }


def _print_human(rep: dict) -> None:
    print(f"RUN {rep['run_dir']}")
    print(f"cases_csv {rep['cases_csv']}")
    print(f"total_cases {rep['total_cases']}")
    print()
    print("=== band counts ===")
    for band, count in sorted(rep["band_counts"].items()):
        print(f"  {band:<35} {count}")
    print()
    print("=== accounting ===")
    for key, value in rep["accounting"].items():
        print(f"  {key:<32} {value}")
    print()
    for key, title in (
        ("orphan_findings", "orphan findings"),
        ("unselected_findings", "findings for unselected cases"),
        ("unmatched_observations", "unmatched observations"),
        ("unmatched_raw_cases", "raw case directories outside selection"),
    ):
        values = rep.get(key, [])
        if values:
            print(f"=== {title} ({len(values)}) ===")
            for value in values:
                print(f"  {value}")
            print()
    if rep["anomalies"]:
        print(f"=== anomalies ({len(rep['anomalies'])}) ===")
        for anomaly in rep["anomalies"]:
            print(f"  {anomaly}")
        print()
    print("=== per-case ===")
    for case in rep["per_case"]:
        print(
            f"{case['case_id']:<22} cat={case['benchmark_category']} "
            f"vuln={case['vulnerable']} disposition={case['primary_disposition']} "
            f"eff={case['effective_scored']}"
        )
        if case["indeterminate_reason"]:
            print(f"  INDET reason={case['indeterminate_reason']}")
        for finding in case["raw_findings"]:
            print(
                f"  finding cls={finding['class']} fam={finding['emitted_family']} "
                f"reason={finding['reason']} eff={finding['effective']}"
            )
        for observation in case["observations"]:
            oid = observation.get("observation_id") or "-"
            print(
                f"  obs {oid:<24} cls={observation.get('classification')!s:<26} "
                f"fired={observation.get('oracle_fired')!s:<6} "
                f"band={observation['diagnostic_band']}"
            )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Recorder-aware diagnostic for a Track A run. "
            "Informational only; does not produce a benchmark score."
        )
    )
    parser.add_argument("run_dir", help="Path to the run directory")
    parser.add_argument(
        "--cases-csv", default=None, help="Override corpus CSV (default: from manifest)"
    )
    parser.add_argument("--json", action="store_true", help="Emit full report as JSON")
    args = parser.parse_args(argv)
    report = diagnose(
        Path(args.run_dir), Path(args.cases_csv) if args.cases_csv else None
    )
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        _print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
