"""ZAP driver for Track A benchmark -- parameterized URLs via automation framework."""
from __future__ import annotations

import json
from pathlib import Path

from benchmark.common.run_utils import run_subprocess


def _seed_url(base: str, case: dict) -> str:
    base = base.rstrip("/")
    path = case["urlpath"]
    param = case.get("param") or case["testname"]
    return f"{base}{path}.html?{param}=SafeText"


def run_zap_v2(run_dir: Path, cases: list[dict], base: str, env: dict) -> int:
    image = env.get("ZAP_IMAGE", "ghcr.io/zaproxy/zaproxy:stable")
    wrk = run_dir.resolve()
    base = base.replace("127.0.0.1", "host.docker.internal").replace("localhost", "host.docker.internal")

    urls = [_seed_url(base, c) for c in cases]
    (run_dir / "urls.txt").write_text("\n".join(urls), encoding="utf-8")

    scope_re = base.rstrip("/") + "/.*"
    y = [
        "env:",
        "  contexts:",
        "    - name: benchmark",
        "      urls:",
    ]
    for u in urls:
        y.append(f'        - "{u}"')
    y.append(f'      includePaths: ["{scope_re}"]')
    y.append("  parameters:")
    y.append("    failOnError: true")
    y.append("    progressToStdout: true")
    y.append("jobs:")
    y.append("  - type: requestor")
    y.append("    parameters:")
    y.append('      user: ""')
    y.append("    requests:")
    for u in urls:
        y.append(f'      - url: "{u}"')
        y.append("        method: GET")
    y.append("  - type: passiveScan-config")
    y.append("    parameters:")
    y.append("      maxAlertsPerRule: 0")
    y.append("      scanOnlyInScope: true")
    y.append("  - type: passiveScan-wait")
    y.append("    parameters:")
    y.append("      maxDuration: 10")
    y.append("  - type: activeScan")
    y.append("    parameters:")
    y.append("      context: benchmark")
    y.append("  - type: report")
    y.append("    parameters:")
    y.append("      template: traditional-json")
    y.append("      reportDir: /zap/wrk/")
    y.append("      reportFile: zap-report")
    (run_dir / "automation.yaml").write_text("\n".join(y), encoding="utf-8")

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{wrk}:/zap/wrk/:rw",
        "-t", image,
        "zap.sh", "-cmd", "-autorun", "/zap/wrk/automation.yaml",
    ]
    code = run_subprocess(cmd, run_dir, timeout=float(env.get("ZAP_TIMEOUT", "3600")))

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
