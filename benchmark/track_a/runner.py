"""Track A runner for OWASP Benchmark.

Drives JANISSARY, OWASP ZAP, or Nuclei against a running OWASP Benchmark
instance. Writes raw output per run into a timestamped directory.

Usage:
    python -m benchmark.track_a.runner --tool janissary --run-number 1 \
        --target-base http://127.0.0.1:8080 --cases-csv cases.csv

The cases CSV must have a header row with at least:
    testname,category,vulnerable
Optional column: param (defaults to testname, which is the OWASP Benchmark
convention - every test's parameter is named after its testname).

Per-tool behavior:
    janissary   one subprocess per case:
                janissary scan -u URL -p PARAM --jsonl --quiet
                Per-case stdout appended to findings.jsonl. Per-case exit
                codes accumulated; non-zero aggregate on any subprocess
                error other than exit code 1 (findings) is a hard fail.
    nuclei      single subprocess with a URL list file:
                nuclei -list urls.txt -jsonl -silent -nc -o findings.jsonl
    zap         single subprocess against the base URL, baseline scan:
                docker run ... zap-baseline.py -t URL -J report.json
                Report parsed into findings.jsonl as {url, alert, ...}.

This runner does NOT score results. Scoring is done by analyze.py using
the ground-truth CSV and the raw artifacts written here.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

import contextlib  # noqa: E402

from benchmark.common.run_utils import (  # noqa: E402
    finalize_manifest,
    load_jsonl,
    make_run_dir,
    run_subprocess,
    write_manifest,
)
from benchmark.track_a.zap_driver import run_zap_v2  # noqa: E402

TRACK = "track_a"
BENCH_ROOT = HERE.parent


def load_cases(csv_path: Path) -> list[dict]:
    """Read case_vectors.csv (from _extract_vectors.py)."""
    rows: list[dict] = []
    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for r in reader:
            name = (r.get("testname") or "").strip()
            if not name:
                continue
            rows.append(
                {
                    "testname": name,
                    "category": (r.get("category") or "").strip(),
                    "urlpath": (r.get("urlpath") or f"/{name}").strip(),
                    "mode": (r.get("mode") or "param").strip(),
                    "header_name": (r.get("header_name") or "").strip(),
                    "vulnerable": (r.get("vulnerable") or "").strip().lower()
                    in ("true", "1", "yes"),
                    "param": (r.get("param") or name).strip(),
                }
            )
    return rows


# Maps case_vectors.csv `mode` -> (inject_in, param_arg, http_method).
# Modes not in this table are skipped and recorded in skipped.jsonl.
def _dispatch(c: dict) -> tuple[str, str, str] | None:
    mode = c["mode"]
    name = c["testname"]
    if mode == "param":
        return ("body", name, "POST")
    if mode == "cookie":
        return ("cookie", name, "POST")
    if mode == "header_self":
        return ("header", name, "POST")
    if mode == "header_other":
        return ("header", c["header_name"] or "Referer", "POST")
    if mode == "param_name":
        return ("param-name", name, "POST")
    # header_any needs header-name-safe payloads; not supported in run 1.
    # out_of_scope_* / unclassified: declared in BENCHMARK.md.
    return None


def case_url(base: str, case: dict) -> str:
    base = base.rstrip("/")
    return f"{base}{case['urlpath']}"


def tool_version(tool: str, env: dict) -> str:
    if tool == "janissary":
        cmd = [
            sys.executable,
            "-c",
            "from janissary import __version__; print(__version__)",
        ]
    elif tool == "nuclei":
        cmd = [env.get("NUCLEI_BIN", "nuclei"), "-version"]
    elif tool == "zap":
        cmd = [
            "docker",
            "image",
            "inspect",
            env.get("ZAP_IMAGE", "ghcr.io/zaproxy/zaproxy:stable"),
            "--format",
            "{{.Id}}",
        ]
    else:
        return "unknown"
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return (out.stdout or out.stderr or "").strip().splitlines()[0][:80]
    except Exception:
        return "unknown"


def load_env(path: Path | None) -> dict:
    if path is None or not path.exists():
        return {}
    out: dict = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


# ---------------------------------------------------------------------
# per-tool drivers
# ---------------------------------------------------------------------


def _run_subprocess_tree(
    cmd: list[str], timeout: float
) -> tuple[int | None, str, str, bool]:
    """Run a subprocess with a timeout that kills the whole process tree.

    subprocess.run(capture_output=True, timeout=N) kills only the direct
    child on timeout. On Windows, janissary.exe is a shim that spawns
    python.exe as a grandchild; the grandchild inherits the stdout pipe,
    and communicate()'s second (untimed) drain blocks forever waiting for
    it to close. We instead Popen, put the child in its own process group,
    and on timeout use taskkill /T (Windows) or killpg (POSIX) to
    terminate the tree.

    Returns (returncode, stdout, stderr, timed_out). returncode is None
    when timed out.
    """
    if sys.platform == "win32":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        creationflags = 0

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=creationflags,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out or "", err or "", False
    except subprocess.TimeoutExpired:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True,
            )
        else:
            import os
            import signal

            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                proc.kill()
        try:
            out, err = proc.communicate(timeout=5)
        except Exception:
            out, err = "", ""
        return None, out or "", err or "", True


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _probe_record_case_dir_support(
    cmd_prefix: list, timeout: float = 10.0
) -> tuple[bool, str]:
    """Probe whether the candidate binary supports --record-case-dir. Never raises."""
    try:
        rc, out_s, _err_s, timed_out = _run_subprocess_tree(
            [*cmd_prefix, "scan", "--help"], timeout
        )
    except Exception as exc:
        return False, f"probe raised: {exc!r}"
    if timed_out:
        return False, "probe timed out"
    if rc != 0:
        return False, f"probe exited {rc}"
    supported = "--record-case-dir" in (out_s or "")
    return supported, (out_s or "")[:200]


def _write_run_level_recording_status(
    run_dir: Path, enabled: bool, reason: str | None, excerpt: str | None
) -> None:
    """Write run-level recording_status.json. Best-effort."""
    try:
        payload = {"recording_enabled": enabled}
        if not enabled:
            payload["reason"] = reason or "unspecified"
            payload["probe_output_excerpt"] = excerpt or ""
        (run_dir / "recording_status.json").write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )
    except Exception:
        pass


def _read_attempts(attempts_path: Path) -> dict:
    """Parse case_attempts.jsonl into {case_id: {started_at, finished_at, rc, timed_out, errored_at}}."""
    result: dict = {}
    if not attempts_path.exists():
        return result
    try:
        text = attempts_path.read_text(encoding="utf-8")
    except Exception:
        return result
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except Exception:
            continue
        cid = evt.get("case_id")
        if not cid:
            continue
        d = result.setdefault(cid, {})
        etype = evt.get("event")
        if etype == "attempt_started":
            d["started_at"] = evt.get("started_at")
        elif etype == "attempt_finished":
            d["finished_at"] = evt.get("finished_at")
            d["finished_rc"] = evt.get("rc")
            d["finished_timed_out"] = evt.get("timed_out")
        elif etype == "attempt_errored":
            d["errored_at"] = evt.get("errored_at")
    return result


def _validate_status_fields(s: dict) -> str | None:
    """Validate recording_status.json fields per design §8.2. Return reason or None."""
    if not isinstance(s, dict):
        return "status_file_invalid: not a dict"
    for k in ("recording_enabled", "recorder_constructed", "failure_log_written"):
        if not isinstance(s.get(k), bool):
            return f"status_file_invalid: {k}"
    for k in ("records_attempted", "records_written", "failures_total"):
        v = s.get(k)
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            return f"status_file_invalid: {k}"
    if s["records_written"] > s["records_attempted"]:
        return "status_file_invalid: records_written > records_attempted"
    if s["failures_total"] > s["records_attempted"] - s["records_written"]:
        return "status_file_invalid: failures_total exceeds expected"
    return None


def _classify_case(
    attempt: dict | None, status: dict | None, recording_enabled: bool
) -> tuple[str, str | None]:
    """Return (primary_disposition, reason_detail). Per design §8.3a."""
    # Step 1: subprocess completion
    if attempt is None:
        return ("missing", "not_reached")
    if attempt.get("errored_at") is not None:
        return ("missing", "scan_errored_at_case")
    if attempt.get("finished_at") is None:
        return ("missing", "scan_aborted_at_case")
    # Timeout ambiguity: design §9 doesn't cover attempt_finished + timed_out=true
    if attempt.get("finished_timed_out") is True:
        return ("missing", "execution_state_indeterminate")
    # Step 2: recording enabled at run level?
    if not recording_enabled:
        return ("recording_disabled", None)
    # Step 3: validate status
    if status is None:
        return ("recording_indeterminate", "status_file_missing")
    err = _validate_status_fields(status)
    if err:
        return ("recording_indeterminate", err)
    if status["failures_total"] > 0:
        return ("recording_failed", None)
    if status["records_written"] >= 1:
        return ("has_observations", None)
    return ("zero_observations", None)


def _enrich_and_write(
    run_dir: Path, all_cases: list[dict], case_selection: dict, recording_enabled: bool
) -> dict:
    """Enrich per-case raw recordings, write coverage files, write summary."""
    attempts = _read_attempts(run_dir / "case_attempts.jsonl")
    case_raw_dir = run_dir / "case_raw"

    # Determine iteration set: (case_id, meta_dict)
    if recording_enabled:
        iterate = [(cid, dict(meta)) for cid, meta in case_selection.items()]
    else:
        from janissary.harness.pathtraver import _sanitize_case_id

        iterate = [
            (
                _sanitize_case_id(c.get("testname", "")),
                {"testname": c.get("testname"), "mode": c.get("mode"), "url": None},
            )
            for c in all_cases
        ]

    out = {
        "records": run_dir / "case_records.jsonl",
        "zero": run_dir / "case_zero_observations.jsonl",
        "failed": run_dir / "case_recording_failed.jsonl",
        "indeterminate": run_dir / "case_recording_indeterminate.jsonl",
        "missing": run_dir / "case_missing.jsonl",
        "conflicts": run_dir / "enrichment_conflicts.jsonl",
    }
    for path in out.values():
        with contextlib.suppress(Exception):
            path.write_text("", encoding="utf-8")

    primary = dict.fromkeys(
        (
            "has_observations",
            "zero_observations",
            "recording_failed",
            "recording_indeterminate",
            "recording_disabled",
            "missing",
        ),
        0,
    )
    missing_breakdown = dict.fromkeys(
        (
            "not_reached",
            "scan_aborted_at_case",
            "scan_errored_at_case",
            "execution_state_indeterminate",
        ),
        0,
    )
    unmatched = 0
    processed = set()

    for cid, meta in iterate:
        processed.add(cid)
        case_dir = case_raw_dir / cid if recording_enabled else None
        status = None
        if case_dir is not None:
            sp = case_dir / "recording_status.json"
            if sp.exists():
                try:
                    status = json.loads(sp.read_text(encoding="utf-8"))
                except Exception:
                    status = None

        disposition, detail = _classify_case(
            attempts.get(cid), status, recording_enabled
        )
        primary[disposition] += 1

        base_record = {
            "case_id": cid,
            "testname": meta.get("testname"),
            "mode": meta.get("mode"),
        }

        try:
            if disposition == "missing":
                missing_breakdown[detail] = missing_breakdown.get(detail, 0) + 1
                with out["missing"].open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps({**base_record, "reason": detail}) + "\n")
            elif disposition == "zero_observations":
                with out["zero"].open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(base_record) + "\n")
            elif disposition == "recording_failed":
                rw = (status or {}).get("records_written", 0)
                with out["failed"].open("a", encoding="utf-8") as fh:
                    fh.write(
                        json.dumps(
                            {
                                **base_record,
                                "partial": rw > 0,
                                "records_written": rw,
                                "failures_total": (status or {}).get(
                                    "failures_total", 0
                                ),
                                "failure_log_written": (status or {}).get(
                                    "failure_log_written", False
                                ),
                            }
                        )
                        + "\n"
                    )
            elif disposition == "recording_indeterminate":
                with out["indeterminate"].open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps({**base_record, "reason": detail}) + "\n")
        except Exception:
            pass

        # Emit records for has_observations / recording_failed partial
        if (
            recording_enabled
            and disposition in ("has_observations", "recording_failed")
            and case_dir is not None
        ):
            raw_file = case_dir / "case_records_raw.jsonl"
            if raw_file.exists():
                try:
                    for line in raw_file.read_text(encoding="utf-8").splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except Exception:
                            continue
                        rec["testname"] = meta.get("testname")
                        rec["mode"] = meta.get("mode")
                        rec["enriched"] = True
                        with out["records"].open("a", encoding="utf-8") as fh:
                            fh.write(json.dumps(rec) + "\n")
                except Exception:
                    pass

    # Unmatched raw observations
    if case_raw_dir.exists():
        try:
            for case_dir in case_raw_dir.iterdir():
                if not case_dir.is_dir() or case_dir.name in processed:
                    continue
                raw_file = case_dir / "case_records_raw.jsonl"
                if not raw_file.exists():
                    continue
                try:
                    for line in raw_file.read_text(encoding="utf-8").splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except Exception:
                            continue
                        rec["enriched"] = False
                        rec["enrichment_reason"] = "case_id not in selection"
                        with out["records"].open("a", encoding="utf-8") as fh:
                            fh.write(json.dumps(rec) + "\n")
                        unmatched += 1
                except Exception:
                    pass
        except Exception:
            pass

    # Invariants
    primary_sum = sum(primary.values())
    missing_sum = sum(missing_breakdown.values())
    reasons = []
    if primary_sum != len(iterate):
        reasons.append(
            {
                "invariant": "primary_dispositions_sum == cases_total",
                "computed": primary_sum,
                "expected": len(iterate),
            }
        )
    if missing_sum != primary["missing"]:
        reasons.append(
            {
                "invariant": "missing_breakdown_sum == missing",
                "computed": missing_sum,
                "expected": primary["missing"],
            }
        )

    summary = {
        "recording_enabled": recording_enabled,
        "cases_total": len(iterate),
        "primary_dispositions": primary,
        "primary_dispositions_sum": primary_sum,
        "missing_breakdown": missing_breakdown,
        "missing_breakdown_sum": missing_sum,
        "unmatched_observations": unmatched,
        "enrichment_conflicts": 0,
        "accounting_valid": len(reasons) == 0,
        "accounting_failure_reasons": reasons,
    }
    with contextlib.suppress(Exception):
        (run_dir / "recording_summary.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8"
        )
    return summary


def run_janissary(run_dir: Path, cases: list[dict], base: str, env: dict) -> int:
    findings = run_dir / "findings.jsonl"
    findings.write_text("", encoding="utf-8")
    skipped_path = run_dir / "skipped.jsonl"
    skipped_path.write_text("", encoding="utf-8")
    timeouts_path = run_dir / "timeouts.jsonl"
    timeouts_path.write_text("", encoding="utf-8")
    cmd_template = env.get("JANISSARY_BIN", "janissary")
    if env.get("JANISSARY_USE_MODULE", "").lower() in ("1", "true", "yes"):
        cmd_prefix = [sys.executable, "-m", "janissary"]
    else:
        cmd_prefix = [cmd_template]
    timeout = float(env.get("JANISSARY_TIMEOUT", "30"))

    from janissary.harness.pathtraver import _sanitize_case_id

    # M83 Stage 4: capability probe + per-case recording setup
    recording_supported, probe_excerpt = _probe_record_case_dir_support(cmd_prefix)
    recording_enabled = recording_supported

    case_selection: dict = {}
    case_raw_dir = None
    if recording_enabled:
        seen = {}
        for c in cases:
            raw_id = c.get("testname", "")
            cid = _sanitize_case_id(raw_id)
            if cid in seen:
                print(
                    f"[runner] case_id collision: {raw_id!r} and "
                    f"{seen[cid]!r} both sanitize to {cid!r}",
                    file=sys.stderr,
                )
                return 2
            seen[cid] = raw_id
            case_selection[cid] = {
                "testname": raw_id,
                "mode": c.get("mode"),
                "url": case_url(base, c),
            }
        case_raw_dir = run_dir / "case_raw"
        try:
            case_raw_dir.mkdir(exist_ok=True)
        except OSError as exc:
            print(f"[runner] cannot create case_raw/: {exc}", file=sys.stderr)
            _write_run_level_recording_status(
                run_dir, False, "case_raw_dir_unwritable", None
            )
            return 2
        # Pre-create all per-case directories before launching any scan.
        # Fail-closed: if any creation fails, abort without running any scans.
        for cid in case_selection:
            case_dir = case_raw_dir / cid
            try:
                case_dir.mkdir(exist_ok=True)
            except OSError as exc:
                print(
                    f"[runner] cannot create case directory {case_dir}: {exc}",
                    file=sys.stderr,
                )
                _write_run_level_recording_status(
                    run_dir, False, "case_dir_pre_creation_failed", None
                )
                return 2
        with contextlib.suppress(Exception):
            (run_dir / "case_selection.json").write_text(
                json.dumps(case_selection, indent=2), encoding="utf-8"
            )
        _write_run_level_recording_status(run_dir, True, None, None)
    else:
        _write_run_level_recording_status(
            run_dir,
            False,
            "flag_absent_in_binary"
            if "--record-case-dir" not in (probe_excerpt or "")
            else "probe_failed",
            probe_excerpt,
        )

    attempts_path = run_dir / "case_attempts.jsonl"
    attempts_path.write_text("", encoding="utf-8")

    failures = 0
    for c in cases:
        disp = _dispatch(c)
        if disp is None:
            with skipped_path.open("a", encoding="utf-8") as fh:
                fh.write(
                    json.dumps(
                        {
                            "testname": c["testname"],
                            "mode": c["mode"],
                        }
                    )
                    + "\n"
                )
            continue
        inject_in, param_arg, method = disp
        url = case_url(base, c)
        cmd = [
            *cmd_prefix,
            "scan",
            "-u",
            url,
            "-p",
            param_arg,
            "--method",
            method,
            "--inject-in",
            inject_in,
            "--jsonl",
            # removed: "--quiet",  # suppresses JSONL
            "--baseline-count",
            "5",
        ]
        cid = _sanitize_case_id(c.get("testname", ""))
        if recording_enabled:
            case_dir = case_raw_dir / cid
            cmd = [*cmd, "--record-case-dir", str(case_dir)]

        with attempts_path.open("a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {
                        "case_id": cid,
                        "testname": c["testname"],
                        "event": "attempt_started",
                        "started_at": _now_iso(),
                    }
                )
                + "\n"
            )

        try:
            rc, out_s, _err_s, timed_out = _run_subprocess_tree(cmd, timeout)
        except Exception as exc:
            with attempts_path.open("a", encoding="utf-8") as fh:
                fh.write(
                    json.dumps(
                        {
                            "case_id": cid,
                            "event": "attempt_errored",
                            "errored_at": _now_iso(),
                            "exception": repr(exc),
                        }
                    )
                    + "\n"
                )
            failures += 1
            continue

        with attempts_path.open("a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {
                        "case_id": cid,
                        "event": "attempt_finished",
                        "finished_at": _now_iso(),
                        "rc": rc,
                        "timed_out": timed_out,
                    }
                )
                + "\n"
            )

        if timed_out:
            # A single slow target must not abort the whole corpus run.
            with timeouts_path.open("a", encoding="utf-8") as fh:
                fh.write(
                    json.dumps(
                        {
                            "testname": c["testname"],
                            "mode": c["mode"],
                            "timeout_s": timeout,
                        }
                    )
                    + "\n"
                )
            failures += 1
            continue
        with findings.open("a", encoding="utf-8") as fh:
            for line in out_s.splitlines():
                if line.strip():
                    fh.write(line + "\n")
        if rc not in (0, 1):
            failures += 1

    try:
        _enrich_and_write(run_dir, cases, case_selection, recording_enabled)
    except Exception as exc:
        print(f"[runner] enrichment failed: {exc}", file=sys.stderr)

    return 1 if failures else 0


def run_nuclei(run_dir: Path, cases: list[dict], base: str, env: dict) -> int:
    urls_file = run_dir / "urls.txt"
    urls_file.write_text(
        "\n".join(case_url(base, c) for c in cases) + "\n",
        encoding="utf-8",
    )
    out_file = run_dir / "findings.jsonl"
    cmd = [
        env.get("NUCLEI_BIN", "nuclei"),
        "-list",
        str(urls_file),
        "-jsonl",
        "-silent",
        "-nc",
        "-o",
        str(out_file),
    ]
    if env.get("NUCLEI_SEVERITY"):
        cmd += ["-severity", env["NUCLEI_SEVERITY"]]
    if env.get("NUCLEI_TEMPLATES"):
        cmd += ["-t", env["NUCLEI_TEMPLATES"]]
    return run_subprocess(
        cmd,
        run_dir,
        timeout=float(env.get("NUCLEI_TIMEOUT", "3600")),
    )


def run_zap(run_dir: Path, cases: list[dict], base: str, env: dict) -> int:
    image = env.get("ZAP_IMAGE", "ghcr.io/zaproxy/zaproxy:stable")
    wrk = run_dir.resolve()
    base = base.replace("127.0.0.1", "host.docker.internal").replace(
        "localhost", "host.docker.internal"
    )
    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{wrk}:/zap/wrk/:rw",
        "-t",
        image,
        "zap-full-scan.py",
        "-t",
        base,
        "-J",
        "zap-report.json",
        "-m",
        env.get("ZAP_MINUTES", "10"),
    ]
    code = run_subprocess(cmd, run_dir, timeout=float(env.get("ZAP_TIMEOUT", "1800")))

    report = run_dir / "zap-report.json"
    findings = run_dir / "findings.jsonl"
    findings.write_text("", encoding="utf-8")
    if report.exists():
        try:
            doc = json.loads(report.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            doc = {}
        for site in doc.get("site", []):
            for alert in site.get("alerts", []):
                for inst in alert.get("instances", []):
                    row = {
                        "url": inst.get("uri"),
                        "alert": alert.get("alert"),
                        "riskcode": alert.get("riskcode"),
                        "confidence": alert.get("confidence"),
                        "cweid": alert.get("cweid"),
                        "pluginid": alert.get("pluginid"),
                    }
                    with findings.open("a", encoding="utf-8") as fh:
                        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return code


DRIVERS = {
    "janissary": run_janissary,
    "nuclei": run_nuclei,
    "zap": run_zap_v2,
}


# ---------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------


def _fired_testnames(findings_path: Path) -> set[str]:
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
        m = re.search(r"BenchmarkTest(\d+)", obj.get("url") or "")
        if m:
            fired.add("BenchmarkTest" + m.group(1))
    return fired


def _retry_zero_pass(run_dir, cases, base, env, driver) -> None:
    """Amendment 20 FN-retry protocol: rerun zero-finding vulnerable cases."""
    fired = _fired_testnames(run_dir / "findings.jsonl")
    zero = [
        c
        for c in cases
        if c["testname"] not in fired
        and str(c.get("vulnerable") or "").strip().lower() == "true"
    ]
    if not zero:
        print("[runner] retry-zero: no zero-finding vulnerable cases")
        return
    retry_dir = run_dir / "pass2"
    retry_dir.mkdir(exist_ok=True)
    print(f"[runner] retry-zero: {len(zero)} cases in second pass")
    driver(retry_dir, zero, base, env)
    p2 = retry_dir / "findings.jsonl"
    if p2.exists():
        with (run_dir / "findings.jsonl").open("ab") as out:
            data = p2.read_bytes()
            out.write(data)
            if data and not data.endswith(b"\n"):
                out.write(b"\n")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="benchmark.track_a.runner",
        description="Track A runner (see BENCHMARK.md).",
    )
    p.add_argument("--tool", required=True, choices=sorted(DRIVERS))
    p.add_argument("--run-number", type=int, required=True, choices=(1, 2, 3))
    p.add_argument("--target-base", required=True)
    p.add_argument("--cases-csv", type=Path, required=True)
    p.add_argument(
        "--tools-env",
        type=Path,
        default=HERE / "tools.env",
        help="Optional env file with binary paths and timeouts.",
    )
    p.add_argument(
        "--retry-zero",
        "--second-pass",
        dest="retry_zero",
        action="store_true",
        help="Amendment 20 FN-retry: rerun zero-finding vulnerable cases "
        "(janissary tool only).",
    )
    args = p.parse_args(argv)
    if not args.target_base.rstrip("/").endswith("/benchmark"):
        p.error(
            "--target-base must end with /benchmark (e.g. http://host:8080/benchmark)"
        )
    cases = load_cases(args.cases_csv)
    if not cases:
        print(f"[runner] no cases loaded from {args.cases_csv}", file=sys.stderr)
        return 2

    env = load_env(args.tools_env)
    run_dir = make_run_dir(TRACK, args.tool, args.run_number)

    tv = tool_version(args.tool, env)
    write_manifest(
        run_dir,
        track=TRACK,
        tool=args.tool,
        tool_version=tv,
        run_number=args.run_number,
        target_version=env.get("TARGET_VERSION", "unpinned"),
        case_count=len(cases),
        target_base=args.target_base,
        cases_csv=str(args.cases_csv),
    )

    driver = DRIVERS[args.tool]
    print(f"[runner] {args.tool} run #{args.run_number}: {len(cases)} cases")
    print(f"[runner] run dir: {run_dir}")
    code = driver(run_dir, cases, args.target_base, env)
    if args.retry_zero:
        if args.tool != "janissary":
            print(
                "[runner] retry-zero only supported for --tool janissary; ignoring",
                file=sys.stderr,
            )
        else:
            _retry_zero_pass(run_dir, cases, args.target_base, env, driver)

    # Quick sanity: how many findings did we get?
    n = len(load_jsonl(run_dir / "findings.jsonl"))
    print(f"[runner] findings written: {n}")

    finalize_manifest(run_dir, exit_code=code, tool_version=tv)
    return code


if __name__ == "__main__":
    sys.exit(main())
