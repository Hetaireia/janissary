"""Tests for Host-header ACL bypass detection (FN-20)."""

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler


class _VulnerableServer(BaseHTTPRequestHandler):
    """Returns 403 for exact-match baseline Host, 200 otherwise.
    Deliberately vulnerable to string-distinct listener-equivalent
    variants. FN-20 verification criterion 2."""

    def do_GET(self):
        host = self.headers.get("Host", "")
        if host in ("app.local", "app.local:80"):
            self.send_response(403)
        else:
            self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class _CorrectServer(BaseHTTPRequestHandler):
    """Parses Host correctly (normalizes trailing dot, splits port).
    FN-20 verification criterion 3."""

    def do_GET(self):
        from urllib.parse import urlparse

        host = self.headers.get("Host", "")
        normalized = host.rstrip(".")
        parsed = urlparse("//" + normalized)
        hostname = (parsed.hostname or "").rstrip(".")
        if hostname in ("app.local", "127.0.0.1"):
            self.send_response(403)
        else:
            self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


def _serve(handler_cls):
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


def test_variant_hosts_enumeration():
    """_variant_hosts produces only listener-equivalent forms.
    FN-20 verification criterion 5."""
    from janissary.integrations.host_bypass import _variant_hosts

    v_http = _variant_hosts("app.local", "http")
    names_http = [n for n, _ in v_http]
    values_http = [v for _, v in v_http]
    assert "explicit_port_80" in names_http
    assert "app.local:80" in values_http
    assert "trailing_dot" in names_http
    assert "app.local." in values_http
    assert "app.local:443" not in values_http
    assert all(":8080" not in v for v in values_http)

    v_https = _variant_hosts("app.local", "https")
    names_https = [n for n, _ in v_https]
    values_https = [v for _, v in v_https]
    assert "explicit_port_443" in names_https
    assert "app.local:443" in values_https
    assert "app.local:80" not in values_https

    v_ported = _variant_hosts("app.local:8080", "http")
    assert v_ported == []


def test_bypass_detected_on_vulnerable_target():
    """Baseline blocked, variant accepted -> finding emitted.
    FN-20 verification criterion 2."""
    from janissary.integrations.host_bypass import test_host_bypass

    srv, port = _serve(_VulnerableServer)
    try:
        url = f"http://127.0.0.1:{port}/"
        findings = test_host_bypass(url, baseline_host="app.local", timeout=2.0)
    finally:
        srv.shutdown()

    assert len(findings) >= 1, (
        f"vulnerable target should produce at least one bypass finding; "
        f"got {len(findings)}"
    )
    names = {f.payload_name for f in findings}
    assert "explicit_port_80" in names or "trailing_dot" in names


def test_no_false_positive_on_correct_target():
    """Correctly-parsing target rejects all variants -> no findings.
    FN-20 verification criterion 3."""
    from janissary.integrations.host_bypass import test_host_bypass

    srv, port = _serve(_CorrectServer)
    try:
        url = f"http://127.0.0.1:{port}/"
        findings = test_host_bypass(url, baseline_host="app.local", timeout=2.0)
    finally:
        srv.shutdown()

    assert findings == [], (
        f"correct target must not produce bypass findings; got {findings}"
    )


def test_no_finding_when_baseline_not_blocked():
    """Baseline 200 -> no bypass to test -> no findings."""
    from janissary.integrations.host_bypass import test_host_bypass

    srv, port = _serve(_VulnerableServer)
    try:
        url = f"http://127.0.0.1:{port}/"
        findings = test_host_bypass(url, baseline_host="other.host", timeout=2.0)
    finally:
        srv.shutdown()

    assert findings == []


def test_finding_shape():
    """Finding fields match FN-20 verification criterion 4."""
    from janissary.integrations.host_bypass import test_host_bypass

    srv, port = _serve(_VulnerableServer)
    try:
        url = f"http://127.0.0.1:{port}/"
        findings = test_host_bypass(url, baseline_host="app.local", timeout=2.0)
    finally:
        srv.shutdown()

    assert findings, "expected at least one finding"
    f = findings[0]
    assert f.category == "host_header"
    assert f.severity == "high"
    assert f.finding_type == "host_header_acl_bypass"
    assert f.param == "Host"
    assert f.response_status == 200
    assert "bypass" in f.detail.lower()


# --- CLI subcommand wiring tests ---


def test_host_bypass_subcommand_invokes_helper(capsys):
    """`janissary host-bypass -u URL` invokes test_host_bypass with args."""
    import sys
    from unittest.mock import patch
    from janissary.cli import main

    called = {}

    def fake(url, baseline_host=None, timeout=5.0):
        called["url"] = url
        called["baseline_host"] = baseline_host
        called["timeout"] = timeout
        return []

    argv = [
        "janissary",
        "host-bypass",
        "-u",
        "http://example.com/",
        "--baseline-host",
        "foo.example",
        "--timeout",
        "2.5",
    ]
    with patch.object(sys, "argv", argv):
        with patch(
            "janissary.integrations.host_bypass.test_host_bypass",
            side_effect=fake,
        ):
            try:
                rc = main()
            except SystemExit as exc:
                rc = exc.code

    assert rc == 0, f"expected rc=0, got {rc}"
    assert called["url"] == "http://example.com/"
    assert called["baseline_host"] == "foo.example"
    assert called["timeout"] == 2.5


def test_host_bypass_subcommand_prints_findings(capsys):
    """Findings print to stdout in expected format."""
    import sys
    from unittest.mock import MagicMock, patch
    from janissary.cli import main

    f = MagicMock()
    f.severity = "high"
    f.finding_type = "host_header_acl_bypass"
    f.url = "http://example.com/"
    f.payload_name = "trailing_dot"
    f.payload_value = "example.com."
    f.response_status = 200
    f.detail = "bypass via trailing_dot"

    argv = ["janissary", "host-bypass", "-u", "http://example.com/"]
    with patch.object(sys, "argv", argv):
        with patch(
            "janissary.integrations.host_bypass.test_host_bypass",
            return_value=[f],
        ):
            try:
                rc = main()
            except SystemExit as exc:
                rc = exc.code

    assert rc == 0
    out = capsys.readouterr().out
    assert "host_header_acl_bypass" in out
    assert "trailing_dot" in out


def test_host_bypass_subcommand_clean_when_no_findings(capsys):
    """No findings prints a clean message and returns 0."""
    import sys
    from unittest.mock import patch
    from janissary.cli import main

    argv = ["janissary", "host-bypass", "-u", "http://example.com/"]
    with patch.object(sys, "argv", argv):
        with patch(
            "janissary.integrations.host_bypass.test_host_bypass",
            return_value=[],
        ):
            try:
                rc = main()
            except SystemExit as exc:
                rc = exc.code

    assert rc == 0
    out = capsys.readouterr().out
    assert "no Host-header ACL bypass" in out


# --- scan wiring tests (FN-20 part 2) ---


def _minimal_candidate():
    from janissary.verification import CandidateFinding

    return CandidateFinding(
        param="Host",
        payload_name="trailing_dot",
        payload_value="app.local.",
        category="host_header",
        severity="high",
        finding_type="host_header_acl_bypass",
        detail="test bypass",
        response_status=200,
        response_length=0,
        url="http://example.com/",
        method="GET",
    )


def _empty_scan_summary():
    from janissary.engine.scanner import ScanSummary

    return ScanSummary(target="http://example.com/", params=["x"], method="GET")


def _scanner_for_wiring():
    from janissary.engine.scanner import Scanner

    return Scanner(target="http://example.com/", params=["x"])


def test_candidate_to_scan_finding_passes_engine_emitted_invariant():
    """Converted finding must pass the asserting list's append check.

    If _engine_emitted isn't set (or can't be set on a frozen dataclass),
    appending to ScanSummary.findings raises AssertionError here.
    """
    scanner = _scanner_for_wiring()
    c = _minimal_candidate()
    f = scanner._candidate_to_scan_finding(c)
    summary = _empty_scan_summary()
    # This append is the assertion: _VerifiedFindingsList checks _engine_emitted
    summary.findings.append(f)
    assert summary.findings[0].finding_type == "host_header_acl_bypass"


def test_scan_host_bypass_returns_populated_summary():
    """scan_host_bypass converts candidates into a ScanSummary."""
    from unittest.mock import patch

    scanner = _scanner_for_wiring()
    c = _minimal_candidate()
    with patch(
        "janissary.integrations.host_bypass.test_host_bypass",
        return_value=[c],
    ):
        summary = scanner.scan_host_bypass()
    assert summary.finding_count == 1
    assert len(summary.findings) == 1
    assert summary.findings[0].finding_type == "host_header_acl_bypass"
    assert summary.method == "HOST-BYPASS"
    assert summary.total_requests == 3


def test_scan_host_bypass_clean_summary():
    """No bypass detected -> empty summary, finding_count 0."""
    from unittest.mock import patch

    scanner = _scanner_for_wiring()
    with patch(
        "janissary.integrations.host_bypass.test_host_bypass",
        return_value=[],
    ):
        summary = scanner.scan_host_bypass()
    assert summary.finding_count == 0
    assert len(summary.findings) == 0
    assert summary.scan_incomplete is False


def test_cmd_scan_invokes_scan_host_bypass_when_flag_set():
    """`scan -u URL --host-bypass` calls Scanner.scan_host_bypass."""
    import sys
    from unittest.mock import patch
    from janissary.cli import main

    argv = [
        "janissary",
        "scan",
        "-u",
        "http://example.com/",
        "--host-bypass",
        "--quiet",
    ]
    with patch.object(sys, "argv", argv):
        with patch("janissary.cli.Scanner") as MockScanner:
            inst = MockScanner.return_value
            inst.scan.return_value = _empty_scan_summary()
            inst.scan_host_bypass.return_value = _empty_scan_summary()
            try:
                rc = main()
            except SystemExit as exc:
                rc = exc.code

    assert rc == 0, f"expected rc=0, got {rc}"
    inst.scan_host_bypass.assert_called_once()


# --- FN-20 follow-up: --baseline-host on scan ---


def test_scan_baseline_host_flag_registered():
    """--baseline-host must parse alongside --host-bypass."""
    from janissary.cli import build_parser

    p = build_parser()
    args = p.parse_args(
        [
            "scan",
            "-u",
            "http://example.com/",
            "--host-bypass",
            "--baseline-host",
            "app.local",
        ]
    )
    assert args.host_bypass is True
    assert args.baseline_host == "app.local"


def test_scan_baseline_host_defaults_none():
    """Absent --baseline-host leaves the value as None."""
    from janissary.cli import build_parser

    p = build_parser()
    args = p.parse_args(
        [
            "scan",
            "-u",
            "http://example.com/",
            "--host-bypass",
        ]
    )
    assert args.baseline_host is None


def test_scan_passes_baseline_host_to_scanner():
    """cmd_scan threads args.baseline_host into scan_host_bypass."""
    import sys
    from unittest.mock import patch
    from janissary.cli import main
    from janissary.engine.scanner import ScanSummary

    empty = ScanSummary(target="http://example.com/", params=["x"], method="GET")
    argv = [
        "janissary",
        "scan",
        "-u",
        "http://example.com/",
        "--host-bypass",
        "--baseline-host",
        "app.local",
        "--quiet",
        "--no-waf",
    ]
    with patch.object(sys, "argv", argv):
        with patch("janissary.cli.Scanner") as MockScanner:
            inst = MockScanner.return_value
            inst.scan.return_value = empty
            inst.scan_host_bypass.return_value = empty
            try:
                rc = main()
            except SystemExit as exc:
                rc = exc.code

    assert rc == 0, f"expected rc=0, got {rc}"
    inst.scan_host_bypass.assert_called_once()
    call_kwargs = inst.scan_host_bypass.call_args.kwargs
    assert call_kwargs.get("baseline_host") == "app.local", (
        f"baseline_host must be passed through; got {call_kwargs!r}"
    )
