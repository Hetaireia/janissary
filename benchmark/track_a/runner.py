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
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from benchmark.common.run_utils import (  # noqa: E402
    finalize_manifest,
    load_jsonl,
    make_run_dir,
    run_subprocess,
    write_manifest,
)

TRACK = "track-a"
BENCH_ROOT = HERE.parent


def load_cases(csv_path: Path) -> list[dict]:
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
                    "vulnerable": (r.get("vulnerable") or "").strip().lower()
                    in ("true", "1", "yes"),
                    "param": (r.get("param") or name).strip(),
                }
            )
    return rows


def case_url(base: str, testname: str) -> str:
    base = base.rstrip("/")
    return f"{base}/{testname}"


def tool_version(tool: str, env: dict) -> str:
    if tool == "janissary":
        cmd = [sys.executable, "-c",
               "from janissary import __version__; print(__version__)"]
    elif tool == "nuclei":
        cmd = [env.get("NUCLEI_BIN", "nuclei"), "-version"]
    elif tool == "zap":
        cmd = ["docker", "image", "inspect",
               env.get("ZAP_IMAGE", "ghcr.io/zaproxy/zaproxy:stable"),
               "--format", "{{.Id}}"]
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


def run_janissary(run_dir: Path, cases: list[dict], base: str, env: dict) -> int:
    findings = run_dir / "findings.jsonl"
    findings.write_text("", encoding="utf-8")
    cmd_template = env.get("JANISSARY_BIN", "janissary")
    timeout = float(env.get("JANISSARY_TIMEOUT", "30"))
    failures = 0
    for c in cases:
        url = case_url(base, c["testname"])
        cmd = [
            cmd_template, "scan",
            "-u", url,
            "-p", c["param"],
            "--jsonl",
            "--quiet",
            "--baseline-count", "5",
        ]
        out = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
        with findings.open("a", encoding="utf-8") as fh:
            for line in (out.stdout or "").splitlines():
                if line.strip():
                    fh.write(line + "\n")
        if out.returncode not in (0, 1):
            failures += 1
    return 1 if failures else 0


def run_nuclei(run_dir: Path, cases: list[dict], base: str, env: dict) -> int:
    urls_file = run_dir / "urls.txt"
    urls_file.write_text(
        "\n".join(case_url(base, c["testname"]) for c in cases) + "\n",
        encoding="utf-8",
    )
    out_file = run_dir / "findings.jsonl"
    cmd = [
        env.get("NUCLEI_BIN", "nuclei"),
        "-list", str(urls_file),
        "-jsonl", "-silent", "-nc",
        "-o", str(out_file),
    ]
    if env.get("NUCLEI_SEVERITY"):
        cmd += ["-severity", env["NUCLEI_SEVERITY"]]
    if env.get("NUCLEI_TEMPLATES"):
        cmd += ["-t", env["NUCLEI_TEMPLATES"]]
    return run_subprocess(
        cmd, run_dir,
        timeout=float(env.get("NUCLEI_TIMEOUT", "3600")),
    )


def run_zap(run_dir: Path, cases: list[dict], base: str, env: dict) -> int:
    image = env.get("ZAP_IMAGE", "ghcr.io/zaproxy/zaproxy:stable")
    wrk = run_dir.resolve()
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{wrk}:/zap/wrk/:rw",
        "-t", image,
        "zap-baseline.py",
        "-t", base,
        "-J", "zap-report.json",
        "-m", env.get("ZAP_MINUTES", "10"),
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
    "zap": run_zap,
}


# ---------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------


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
        "--tools-env", type=Path,
        default=HERE / "tools.env",
        help="Optional env file with binary paths and timeouts.",
    )
    args = p.parse_args(argv)

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

    # Quick sanity: how many findings did we get?
    n = len(load_jsonl(run_dir / "findings.jsonl"))
    print(f"[runner] findings written: {n}")

    finalize_manifest(run_dir, exit_code=code, tool_version=tv)
    return code


if __name__ == "__main__":
    sys.exit(main())
