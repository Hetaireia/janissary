"""Track B runner for the operational WAF-survivability benchmark.

Track B has a single target (OWASP Juice Shop behind Cloudflare free
tier) and one run per tool. The metrics recorded are operational, not
statistical: did the tool complete, when did WAF blocking begin, was the
source IP banned after the run.

Block detection
---------------
The tool itself may or may not log WAF responses. Rather than parse each
tool's output format, this runner runs an out-of-band probe:

  * spawn the scan as a subprocess
  * every PROBE_INTERVAL_S seconds, send a benign GET to the target
  * record the wall-clock time of the first probe whose response looks
    like a WAF block (status 403/429/503, or a body containing common
    Cloudflare challenge markers)
  * when the scan exits, wait POST_SCAN_WAIT_S seconds, probe once more;
    if that final probe is still blocked, `ip_banned_after = True`

This makes the block metric tool-agnostic: the same probe classifies
ZAP, Nuclei, and JANISSARY.

Scan completion
---------------
`scan_completed = (subprocess exit code in {0, 1})`. For JANISSARY, both
0 and 1 are successful scans (0 = no findings, 1 = findings). Higher
codes are failures. For ZAP and Nuclei the same convention applies for
the runner's purposes; a tool that crashes or times out is not complete.

Usage
-----
    python -m benchmark.track_b.runner --tool janissary \
        --target-url https://juice.example.com \
        --cases-csv ../track_a/cases.csv  # optional

Cases CSV is not used for scoring here (Track B is operational), but if
supplied, the runner will try to map JANISSARY's findings to ground
truth for the false-positive count. In practice Juice Shop does not
ship a labelled CSV; leave it off and FP counts are marked null.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))

from benchmark.common.run_utils import (  # noqa: E402
    finalize_manifest,
    load_jsonl,
    make_run_dir,
    write_manifest,
)

TRACK = "track_b"
PROBE_INTERVAL_S = 5.0
POST_SCAN_WAIT_S = 30.0
BLOCK_STATUSES = {403, 429, 503}
CHALLENGE_MARKERS = (
    b"cf-chl-",
    b"__cf_chl",
    b"Just a moment",
    b"cf-error-details",
    b"Attention Required! | Cloudflare",
)


def looks_blocked(status: int, body: bytes) -> bool:
    if status in BLOCK_STATUSES:
        return True
    return any(marker in body for marker in CHALLENGE_MARKERS)


def probe(target_url: str, timeout: float = 10.0) -> tuple[int, bytes] | None:
    import urllib.request
    req = urllib.request.Request(
        target_url, method="GET",
        headers={"User-Agent": "janissary-bench-probe/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(4096)
            return resp.status, body
    except Exception as exc:
        # urllib raises on 4xx/5xx; pull the code if it's an HTTPError.
        code = getattr(exc, "code", None)
        if isinstance(code, int):
            try:
                body = exc.read(4096)
            except Exception:
                body = b""
            return code, body
        return None


class ProbeWatcher(threading.Thread):
    """Polls the target every PROBE_INTERVAL_S and records block onset."""

    def __init__(self, target_url: str, stop_event: threading.Event):
        super().__init__(daemon=True)
        self.target_url = target_url
        self.stop_event = stop_event
        self.first_block_at: float | None = None
        self.t0 = 0.0
        self.samples: list[dict] = []

    def run(self) -> None:
        self.t0 = time.perf_counter()
        while not self.stop_event.is_set():
            r = probe(self.target_url)
            elapsed = time.perf_counter() - self.t0
            if r is None:
                self.samples.append({"t": round(elapsed, 2), "status": None, "blocked": False})
            else:
                status, body = r
                blocked = looks_blocked(status, body)
                self.samples.append({"t": round(elapsed, 2), "status": status, "blocked": blocked})
                if blocked and self.first_block_at is None:
                    self.first_block_at = elapsed
            self.stop_event.wait(PROBE_INTERVAL_S)


# ---------------------------------------------------------------------
# per-tool invocation
# ---------------------------------------------------------------------


def build_cmd(tool: str, target_url: str, run_dir: Path, env: dict) -> list[str]:
    if tool == "janissary":
        cmd = [
            env.get("JANISSARY_BIN", "janissary"), "scan",
            "-u", target_url,
            "-p", env.get("JANISSARY_PARAM", "q"),
            "--jsonl", "--quiet",
        ]
        return cmd
    if tool == "nuclei":
        # Nuclei needs a template set; the operator must pin it in tools.env.
        templates = env.get("NUCLEI_TEMPLATES", "")
        cmd = [
            env.get("NUCLEI_BIN", "nuclei"),
            "-u", target_url,
            "-jsonl", "-silent", "-nc",
            "-o", str(run_dir / "findings.jsonl"),
        ]
        if templates:
            cmd += ["-t", templates]
        if env.get("NUCLEI_SEVERITY"):
            cmd += ["-severity", env["NUCLEI_SEVERITY"]]
        return cmd
    if tool == "zap":
        image = env.get("ZAP_IMAGE", "ghcr.io/zaproxy/zaproxy:stable")
        return [
            "docker", "run", "--rm",
            "-v", f"{run_dir.resolve()}:/zap/wrk/:rw",
            "-t", image,
            "zap-baseline.py",
            "-t", target_url,
            "-J", "zap-report.json",
            "-m", env.get("ZAP_MINUTES", "10"),
        ]
    raise ValueError(f"unknown tool: {tool}")


def zap_to_jsonl(run_dir: Path) -> None:
    report = run_dir / "zap-report.json"
    out = run_dir / "findings.jsonl"
    if not report.exists():
        return
    try:
        doc = json.loads(report.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return
    with out.open("w", encoding="utf-8") as fh:
        for site in doc.get("site", []):
            for alert in site.get("alerts", []):
                for inst in alert.get("instances", []):
                    fh.write(json.dumps({
                        "url": inst.get("uri"),
                        "alert": alert.get("alert"),
                        "riskcode": alert.get("riskcode"),
                        "cweid": alert.get("cweid"),
                    }) + "\n")


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


# ---------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="benchmark.track_b.runner",
        description="Track B runner (see BENCHMARK.md).",
    )
    p.add_argument("--tool", required=True, choices=("janissary", "nuclei", "zap"))
    p.add_argument("--target-url", required=True)
    p.add_argument("--tools-env", type=Path, default=HERE / "tools.env")
    args = p.parse_args(argv)

    env = load_env(args.tools_env)
    tv = tool_version(args.tool, env)

    run_dir = make_run_dir(TRACK, args.tool, 1)
    write_manifest(
        run_dir,
        track=TRACK,
        tool=args.tool,
        tool_version=tv,
        run_number=1,
        target_url=args.target_url,
        target_version=env.get("TARGET_VERSION", "unpinned"),
    )

    print(f"[track-b] {args.tool} -> {args.target_url}")
    print(f"[track-b] run dir: {run_dir}")

    stop_event = threading.Event()
    watcher = ProbeWatcher(args.target_url, stop_event)
    watcher.start()

    cmd = build_cmd(args.tool, args.target_url, run_dir, env)
    print(f"[track-b] cmd: {' '.join(cmd)}")

    t_scan_start = time.perf_counter()
    stdout_path = run_dir / "stdout.log"
    stderr_path = run_dir / "stderr.log"
    exit_code = 127
    try:
        with stdout_path.open("w", encoding="utf-8", errors="replace") as out_fh, \
             stderr_path.open("w", encoding="utf-8", errors="replace") as err_fh:
            proc = subprocess.run(
                cmd, stdout=out_fh, stderr=err_fh,
                env={**os.environ, **env}, check=False,
            )
            exit_code = proc.returncode
    except FileNotFoundError as exc:
        stderr_path.write_text(f"[track-b] command not found: {exc}\n", encoding="utf-8")
        exit_code = 127

    scan_time = time.perf_counter() - t_scan_start
    (run_dir / "elapsed.txt").write_text(f"{scan_time:.3f}\n", encoding="utf-8")

    print(f"[track-b] scan exited: code={exit_code} elapsed={scan_time:.1f}s")
    print(f"[track-b] waiting {POST_SCAN_WAIT_S:.0f}s before post-scan probe...")
    stop_event.set()
    watcher.join(timeout=15.0)

    # Post-scan probe: is the IP still blocked?
    time.sleep(POST_SCAN_WAIT_S)
    post = probe(args.target_url)
    ip_banned_after = False
    if post is not None:
        status, body = post
        ip_banned_after = looks_blocked(status, body)
        print(f"[track-b] post-scan probe: status={status} banned={ip_banned_after}")
    else:
        print("[track-b] post-scan probe: unreachable")

    if args.tool == "zap":
        zap_to_jsonl(run_dir)

    findings = load_jsonl(run_dir / "findings.jsonl")
    grouped_ids = {f.get("root_cause_group") for f in findings if f.get("root_cause_group")}

    result = {
        "scan_completed": exit_code in (0, 1),
        "exit_code": exit_code,
        "scan_time_s": round(scan_time, 3),
        "time_to_first_block_s": round(watcher.first_block_at, 3) if watcher.first_block_at else None,
        "ip_banned_after": ip_banned_after,
        "total_findings": len(findings),
        "grouped_findings_count": len(grouped_ids) if grouped_ids else None,
        "probe_samples": watcher.samples[:200],
    }
    (run_dir / "track_b_result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(f"[track-b] result written: {run_dir / 'track_b_result.json'}")
    print(json.dumps(result, indent=2))

    finalize_manifest(run_dir, exit_code=exit_code, tool_version=tv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
