"""Regression suite for Phase 0.2(a) — juice-shop precision.

See docs/ROADMAP.md Phase 0.2(a).

Coverage:
- Roadmap assertion #1 (wordpress_admin produces zero emissions on SPA)
  is DROPPED: the wordpress_admin module no longer exists in the codebase.
  If a future module reintroduces that pattern, add its regression here.
- Roadmap assertion #2 (missed SQLi reported, not silently dropped) is
  covered by test_missed_sqli_reported_not_silently_dropped, live against
  a running juice-shop container.
- Roadmap assertion #3 (401 mid-scan produces scan_incomplete flag) is
  covered by tests/unit/test_scan_incomplete.py: defaults, preflight
  abort (False), mid-scan abort (True), JSON envelope, human print,
  source-level tripwire. Full end-to-end mid-scan simulation against
  juice-shop would require forcing payloads to 401 while baseline is
  clean — deferred until a fixture HTTP server is available.

Juice-shop prerequisite:
  Container must be running. Start with:
    docker run -d -p 3000:3000 --name janissary-trackc-juice bkimminich/juice-shop:v17.1.1

  Behavior:
    - Container absent (default): test SKIPs.
    - Container absent with JANISSARY_INTEGRATION=1 set: test FAILs
      with instructions, so CI gating can rely on it running.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

from janissary.engine.scanner import Scanner


JANISSARY_REPO = Path(__file__).parent.parent.parent
JUICE_LOGIN = (
    JANISSARY_REPO / "benchmark" / "track_c" / "templates" / "juice_login.json"
)
JUICE_URL = "http://127.0.0.1:3000/rest/user/login"


def _juice_container_up() -> bool:
    try:
        r = subprocess.run(
            [
                "docker",
                "ps",
                "--filter",
                "name=janissary-trackc-juice",
                "--format",
                "{{.Names}}",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return "janissary-trackc-juice" in (r.stdout or "")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _require_juice() -> None:
    if _juice_container_up():
        return
    if os.environ.get("JANISSARY_INTEGRATION"):
        pytest.fail(
            "JANISSARY_INTEGRATION=1 but juice-shop container is not running. "
            "Start it with: docker run -d -p 3000:3000 --name janissary-trackc-juice "
            "bkimminich/juice-shop:v17.1.1"
        )
    pytest.skip(
        "juice-shop not running — set JANISSARY_INTEGRATION=1 to fail instead of skip"
    )


def test_missed_sqli_reported_not_silently_dropped():
    """FN-12 regression: SQLi on a 401-baseline endpoint must appear in
    findings as unproven, not silently vanish. See LIMITATIONS.md FN-12
    and commit faade6c."""
    _require_juice()
    template = json.loads(JUICE_LOGIN.read_text(encoding="utf-8"))
    s = Scanner(
        target=JUICE_URL,
        params=["email"],
        method="POST",
        inject_in="json-body",
        json_template=template,
    )
    summary = s.scan(quiet=True)

    assert len(summary.findings) > 0, (
        "FN-12 regression: 0 findings on juice-shop. Was the fix reverted, "
        "or has juice-shop stopped 500-ing on the ' payload? Check with: "
        "curl -X POST http://127.0.0.1:3000/rest/user/login "
        '-H \'Content-Type: application/json\' -d \'{"email":"\'","password":"x"}\''
    )
    statuses = {f.verification_status for f in summary.findings}
    assert "unproven" in statuses, (
        f"FN-12 regression: findings present but none marked unproven. "
        f"Statuses seen: {statuses}. CorroboratorConfirmer may have been removed."
    )
    categories = {f.category for f in summary.findings}
    assert "sqli" in categories, (
        f"FN-12 regression: findings exist but none categorized sqli. "
        f"Categories: {categories}. Template _categories may have been lost."
    )
