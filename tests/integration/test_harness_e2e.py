"""M83 Stage 5: real-fixture end-to-end harness test.

Exercises run_janissary end-to-end against a local HTTP fixture and a real
`janissary scan` subprocess. Verifies all seven coverage artifacts appear
with accounting_valid: true and at least one has_observations record.
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

import pytest

from benchmark.track_a import runner


class _FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def _respond(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = ""
        if length > 0:
            body = self.rfile.read(length).decode("utf-8", errors="replace")
        haystack = unquote(self.path) + " " + unquote(body)
        if "_janissary_noexist_" in haystack:
            text = "file doesn't exist yet"
        elif "etc/passwd" in haystack:
            text = "file already exists"
        else:
            text = "no traversal signal here"
        data = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._respond()

    def do_POST(self):
        self._respond()


@pytest.fixture
def fixture_base():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        thread.join(timeout=5)


def test_end_to_end_real_subprocess(tmp_path, fixture_base):
    bin_path = Path(sys.executable).parent / "janissary"
    if not bin_path.exists():
        pytest.skip(f"janissary binary not found at {bin_path}")

    run_dir = tmp_path / "run"
    run_dir.mkdir()

    cases = [
        {"testname": "T0", "mode": "param", "urlpath": "/scan"},
        {"testname": "T1", "mode": "param", "urlpath": "/scan"},
    ]

    env = {
        "JANISSARY_BIN": str(bin_path),
        "JANISSARY_TIMEOUT": "30",
    }

    rc = runner.run_janissary(run_dir, cases, fixture_base, env)
    assert rc == 0, f"run_janissary returned {rc}"

    required = [
        "case_records.jsonl",
        "case_zero_observations.jsonl",
        "case_recording_failed.jsonl",
        "case_recording_indeterminate.jsonl",
        "case_missing.jsonl",
        "enrichment_conflicts.jsonl",
        "recording_summary.json",
    ]
    for name in required:
        assert (run_dir / name).exists(), f"missing artifact: {name}"

    summary = json.loads((run_dir / "recording_summary.json").read_text())
    assert summary["accounting_valid"] is True
    assert summary["cases_total"] == 2
    assert summary["primary_dispositions_sum"] == 2
    assert summary["primary_dispositions"]["has_observations"] >= 1

    run_status = json.loads((run_dir / "recording_status.json").read_text())
    assert run_status["recording_enabled"] is True

    case_raw = run_dir / "case_raw"
    assert case_raw.exists()
    found_raw = False
    for cd in case_raw.iterdir():
        if not cd.is_dir():
            continue
        raw = cd / "case_records_raw.jsonl"
        if raw.exists() and raw.read_text().strip():
            found_raw = True
            break
    assert found_raw, "no case_records_raw.jsonl with content produced"
