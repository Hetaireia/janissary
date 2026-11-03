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
        "janissary", "host-bypass",
        "-u", "http://example.com/",
        "--baseline-host", "foo.example",
        "--timeout", "2.5",
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
