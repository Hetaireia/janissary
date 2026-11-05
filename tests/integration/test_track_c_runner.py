"""Tests for runner --sessions-file support (M43.5, ADR-026)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TRACK_C = _REPO_ROOT / "benchmark" / "track_c"
if str(_TRACK_C) not in sys.path:
    sys.path.insert(0, str(_TRACK_C))

from runner import scan_case  # noqa: E402


def _minimal_case():
    return {
        "path": "/workshop/api/shop/products",
        "method": "GET",
        "param": "x",
        "vuln_class": "safe",
        "safe": "true",
        "expected_finding_class": "",
        "notes": "",
        "inject_in": "",
        "baseline_value": "",
    }


def _minimal_cfg():
    return {"base_url": "http://127.0.0.1:8888", "healthcheck": "/"}


def _run_scan_case(tmp_path, session, sessions_file=None, sessions_count=None):
    captured = []

    def _fake_run(cmd, **kwargs):
        captured.append(cmd)
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=_fake_run):
        record = scan_case(
            _minimal_cfg(),
            session,
            _minimal_case(),
            tmp_path,
            0,
            sessions_file=sessions_file,
            sessions_count=sessions_count,
        )
    cmd = captured[0] if captured else []
    return cmd, record


def test_no_sessions_file_no_sessions_flag(tmp_path):
    s = requests.Session()
    cmd, record = _run_scan_case(tmp_path, s)
    assert "--sessions" not in cmd
    assert "sessions_used" not in record


def test_sessions_file_adds_sessions_flag_and_sessions_used(tmp_path):
    s = requests.Session()
    cmd, record = _run_scan_case(
        tmp_path,
        s,
        sessions_file="/tmp/sess.json",
        sessions_count=2,
    )
    assert "--sessions" in cmd
    idx = cmd.index("--sessions")
    assert cmd[idx + 1] == "/tmp/sess.json"
    assert record["sessions_used"] == 2


def test_sessions_file_drops_bearer_and_cookie(tmp_path):
    s = requests.Session()
    s._jns_bearer = "fake.jwt.token"
    s.cookies.set("session", "abc")

    # With sessions_file: --bearer/--cookie must be ABSENT (mutual exclusion)
    cmd_with, _ = _run_scan_case(
        tmp_path,
        s,
        sessions_file="/tmp/sess.json",
        sessions_count=2,
    )
    assert "--bearer" not in cmd_with
    assert "--cookie" not in cmd_with

    # Without sessions_file: --bearer and --cookie must be PRESENT
    cmd_without, _ = _run_scan_case(tmp_path, s)
    assert "--bearer" in cmd_without
    assert "--cookie" in cmd_without


def test_no_sessions_file_omits_sessions_used(tmp_path):
    s = requests.Session()
    _, record = _run_scan_case(tmp_path, s)
    assert "sessions_used" not in record


def test_main_rejects_missing_sessions_file():
    missing = "C:\\\\definitely_not_here_9c3f1a.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmark.track_c.runner",
            "--app",
            "crapi",
            "--sessions-file",
            missing,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        cwd=str(_REPO_ROOT),
    )
    assert result.returncode != 0
    combined = (result.stdout + result.stderr).lower()
    assert "not found" in combined or "no such file" in combined
