"""Unit tests for the differential detection engine.

Every test asserts either that a gate fires on a real signal, or that
it does NOT fire on benign input. The negative tests are the point —
they are what proves the false-positive problem is fixed.
"""

from janissary.detection import (
    Baseline,
    DifferentialAnalyzer,
    ResponseSnapshot,
    normalize_body,
)

# ===================================================================
# FIXTURES
# ===================================================================


class FakeResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(self, status=200, text="", content_type="text/html", elapsed=0.1):
        self.status_code = status
        self.text = text
        self.headers = {"content-type": content_type}
        self._elapsed = elapsed

    @property
    def elapsed(self):
        outer = self

        class Elapsed:
            def total_seconds(self):
                return outer._elapsed

        return Elapsed()


def snap(**kwargs):
    """Build a ResponseSnapshot from FakeResponse kwargs."""
    return ResponseSnapshot.from_response(FakeResponse(**kwargs))


def make_baseline(bodies, elapsed=0.1, elapsed_var=0.0):
    """Build a Baseline from a list of response bodies."""
    b = Baseline()
    for i, body in enumerate(bodies):
        b.add(snap(text=body, elapsed=elapsed + i * elapsed_var))
    return b


# ===================================================================
# NORMALIZATION
# ===================================================================


def test_normalization_strips_csrf():
    a = '<input name="csrf_token" value="aaa111">'
    b = '<input name="csrf_token" value="bbb222">'
    assert normalize_body(a) == normalize_body(b)


def test_normalization_strips_timestamps():
    a = "Created at 2026-01-15T10:23:45Z"
    b = "Created at 2026-09-24T18:01:02Z"
    assert normalize_body(a) == normalize_body(b)


def test_normalization_strips_uuids():
    a = "id=550e8400-e29b-41d4-a716-446655440000"
    b = "id=6ba7b810-9dad-11d1-80b4-00c04fd430c8"
    assert normalize_body(a) == normalize_body(b)


def test_normalization_strips_session_ids():
    a = "url;jsessionid=AABBCCDDEEFF112233"
    b = "url;jsessionid=998877665544332211"
    assert normalize_body(a) == normalize_body(b)


def test_normalization_preserves_real_content():
    a = "<html><body>Hello World</body></html>"
    assert "Hello World" in normalize_body(a)


def test_normalization_collapses_whitespace():
    a = "<html>   <body>\n\n\tHello</body></html>"
    b = "<html> <body> Hello</body></html>"
    assert normalize_body(a) == normalize_body(b)


# ===================================================================
# DB ERROR GATE
# ===================================================================


def test_db_error_fires_on_real_mysql_error():
    baseline = make_baseline(["<html>OK</html>"] * 5)
    a = DifferentialAnalyzer(baseline, "sql_single_quote", "'", "sqli")
    resp = snap(text="You have an error in your SQL syntax near '''")
    findings = a.analyze(resp)
    assert any(f["type"] == "db_error" for f in findings)


def test_db_error_fires_on_oracle_error():
    baseline = make_baseline(["<html>OK</html>"] * 5)
    a = DifferentialAnalyzer(baseline, "sql_single_quote", "'", "sqli")
    resp = snap(text="ORA-01756: quoted string not properly terminated")
    findings = a.analyze(resp)
    assert any(f["type"] == "db_error" and f["dbms"] == "oracle" for f in findings)


def test_db_error_does_not_fire_on_generic_syntax_error():
    """The old keyword-matching engine flagged this. The new one must not."""
    baseline = make_baseline(["<html>OK</html>"] * 5)
    a = DifferentialAnalyzer(baseline, "sql_single_quote", "'", "sqli")
    resp = snap(text="<script>SyntaxError: Unexpected token</script>")
    findings = a.analyze(resp)
    assert not any(f["type"] == "db_error" for f in findings)


def test_db_error_does_not_fire_when_baseline_has_it():
    """If the baseline already contains the pattern, it is not a finding."""
    baseline = make_baseline(["Warning: mysql_connect(): ..."] * 5)
    a = DifferentialAnalyzer(baseline, "sql_single_quote", "'", "sqli")
    resp = snap(text="Warning: mysql_connect(): ...")
    findings = a.analyze(resp)
    assert not any(f["type"] == "db_error" for f in findings)


def test_db_error_does_not_fire_on_reflected_payload():
    """If the payload itself contains the error string, reflection would
    otherwise trigger the finding. The gate must check the payload."""
    baseline = make_baseline(["<html>OK</html>"] * 5)
    payload = "You have an error in your SQL syntax"
    a = DifferentialAnalyzer(baseline, "sql_single_quote", payload, "sqli")
    resp = snap(text=f"<html>{payload}</html>")
    findings = a.analyze(resp)
    assert not any(f["type"] == "db_error" for f in findings)


def test_db_error_does_not_fire_on_empty_body():
    baseline = make_baseline(["<html>OK</html>"] * 5)
    a = DifferentialAnalyzer(baseline, "sql_single_quote", "'", "sqli")
    resp = snap(text="")
    findings = a.analyze(resp)
    assert not any(f["type"] == "db_error" for f in findings)


# ===================================================================
# REFLECTION GATE
# ===================================================================


def test_xss_fires_on_unescaped_reflection():
    baseline = make_baseline(["<html>OK</html>"] * 5)
    a = DifferentialAnalyzer(baseline, "xss_script", "<script>alert(1)</script>", "xss")
    resp = snap(text="<html><body><script>alert(1)</script></body></html>")
    findings = a.analyze(resp)
    assert any(
        f["type"] == "reflected_xss" and f["severity"] == "high" for f in findings
    )


def test_xss_does_not_fire_on_escaped_reflection():
    baseline = make_baseline(["<html>OK</html>"] * 5)
    a = DifferentialAnalyzer(baseline, "xss_script", "<script>alert(1)</script>", "xss")
    resp = snap(text="<html>&lt;script&gt;alert(1)&lt;/script&gt;</html>")
    findings = a.analyze(resp)
    assert not any(f["type"] == "reflected_xss" for f in findings)
    assert any(f["type"] == "reflected_xss_safe" for f in findings)


def test_xss_does_not_fire_in_json_content_type():
    baseline = make_baseline(["{}"] * 5)
    a = DifferentialAnalyzer(baseline, "xss_script", "<script>alert(1)</script>", "xss")
    resp = snap(
        text='{"echo": "<script>alert(1)</script>"}', content_type="application/json"
    )
    findings = a.analyze(resp)
    assert not any(f["type"] == "reflected_xss" for f in findings)


def test_xss_does_not_fire_when_payload_not_reflected():
    baseline = make_baseline(["<html>OK</html>"] * 5)
    a = DifferentialAnalyzer(baseline, "xss_script", "<script>alert(1)</script>", "xss")
    resp = snap(text="<html><body>Nothing here</body></html>")
    findings = a.analyze(resp)
    assert not any(f["type"] == "reflected_xss" for f in findings)


def test_non_xss_reflection_is_low_severity():
    baseline = make_baseline(["<html>OK</html>"] * 5)
    a = DifferentialAnalyzer(baseline, "sql_single_quote", "test123", "sqli")
    resp = snap(text="<html>You searched for test123</html>")
    findings = a.analyze(resp)
    reflected = [f for f in findings if f["type"] == "payload_reflected"]
    assert reflected
    assert all(f["severity"] == "low" for f in reflected)


# ===================================================================
# TIMING GATE
# ===================================================================


def test_timing_does_not_fire_on_static_page():
    """A flat baseline has no timing oracle. The gate must not fire."""
    baseline = make_baseline(["<html>OK</html>"] * 5, elapsed=0.1)
    a = DifferentialAnalyzer(baseline, "sql_sleep_mysql", "' OR SLEEP(5)--", "sqli")
    resp = snap(text="<html>OK</html>", elapsed=7.0)
    findings = a.analyze(resp)
    assert not any(f["type"] == "timing_anomaly" for f in findings)


def test_timing_fires_on_variable_baseline():
    baseline = make_baseline(["<html>OK</html>"] * 8, elapsed=0.5, elapsed_var=0.03)
    a = DifferentialAnalyzer(baseline, "sql_sleep_mysql", "' OR SLEEP(5)--", "sqli")
    resp = snap(text="<html>OK</html>", elapsed=6.0)
    findings = a.analyze(resp)
    assert any(f["type"] == "timing_anomaly" for f in findings)


def test_timing_does_not_fire_when_payload_returned_early():
    """Sleep payload returned in 1s but declared floor is 5s."""
    baseline = make_baseline(["<html>OK</html>"] * 8, elapsed=0.5, elapsed_var=0.03)
    a = DifferentialAnalyzer(baseline, "sql_sleep_mysql", "' OR SLEEP(5)--", "sqli")
    resp = snap(text="<html>OK</html>", elapsed=1.0)
    findings = a.analyze(resp)
    assert not any(f["type"] == "timing_anomaly" for f in findings)


def test_timing_does_not_fire_for_non_sleep_payload():
    """A non-sleep payload with no declared floor must not fire timing."""
    baseline = make_baseline(["<html>OK</html>"] * 8, elapsed=0.5, elapsed_var=0.03)
    a = DifferentialAnalyzer(baseline, "sql_single_quote", "'", "sqli")
    resp = snap(text="<html>OK</html>", elapsed=6.0)
    findings = a.analyze(resp)
    assert not any(f["type"] == "timing_anomaly" for f in findings)


# ===================================================================
# STATUS GATE
# ===================================================================


def test_status_does_not_fire_on_404_baseline():
    """A 404 baseline is not an oracle. A 500 from a 404 baseline is not
    a finding."""
    baseline = Baseline()
    for _ in range(5):
        baseline.add(
            ResponseSnapshot(
                status=404,
                body="Not found",
                normalized="Not found",
                fingerprint="x",
                length=9,
                normalized_length=9,
                elapsed=0.1,
                content_type="text/html",
            )
        )
    a = DifferentialAnalyzer(baseline, "sql_single_quote", "'", "sqli")
    resp = snap(status=500, text="Server error")
    findings = a.analyze(resp)
    assert not any(f["type"] == "status_change" for f in findings)


def test_status_fires_on_500_from_200_baseline():
    baseline = make_baseline(["<html>OK</html>"] * 5)
    a = DifferentialAnalyzer(baseline, "sql_single_quote", "'", "sqli")
    resp = snap(status=500, text="Internal Server Error")
    findings = a.analyze(resp)
    assert any(f["type"] == "status_change" for f in findings)


def test_status_does_not_fire_on_302_from_200_baseline():
    """Redirects are not 5xx server errors."""
    baseline = make_baseline(["<html>OK</html>"] * 5)
    a = DifferentialAnalyzer(baseline, "sql_single_quote", "'", "sqli")
    resp = snap(status=302, text="")
    findings = a.analyze(resp)
    assert not any(f["type"] == "status_change" for f in findings)


# ===================================================================
# LENGTH GATE
# ===================================================================


def test_length_does_not_fire_on_unstable_baseline():
    """If the baseline body varies between samples, length is not
    trustworthy and the gate must stay closed."""
    baseline = make_baseline(
        [
            "<html>OK 1</html>",
            "<html>OK 2</html>",
            "<html>OK 3</html>",
            "<html>OK 4</html>",
            "<html>OK 5</html>",
        ]
    )
    a = DifferentialAnalyzer(baseline, "sql_single_quote", "'", "sqli")
    resp = snap(text="<html>" + "X" * 100_000 + "</html>")
    findings = a.analyze(resp)
    assert not any(f["type"] == "length_anomaly" for f in findings)


def test_length_fires_on_stable_baseline_with_huge_response():
    baseline = make_baseline(["<html>OK</html>"] * 5)
    a = DifferentialAnalyzer(baseline, "sql_single_quote", "'", "sqli")
    resp = snap(text="<html>" + "X" * 10_000 + "</html>")
    findings = a.analyze(resp)
    assert any(f["type"] == "length_anomaly" for f in findings)


# ===================================================================
# COMBINED / REGRESSION
# ===================================================================


def test_clean_response_produces_no_findings():
    """The most important test: a benign response must produce nothing."""
    baseline = make_baseline(
        ["<html>Welcome</html>"] * 5, elapsed=0.3, elapsed_var=0.02
    )
    a = DifferentialAnalyzer(baseline, "sql_single_quote", "'", "sqli")
    resp = snap(text="<html>Welcome</html>", elapsed=0.3)
    findings = a.analyze(resp)
    assert findings == []


def test_multiple_gates_can_fire_together():
    """A response can trigger more than one gate. That is fine."""
    baseline = make_baseline(["<html>OK</html>"] * 5)
    a = DifferentialAnalyzer(baseline, "sql_single_quote", "'", "sqli")
    resp = snap(
        status=500,
        text="You have an error in your SQL syntax near '''" + "X" * 10_000,
    )
    findings = a.analyze(resp)
    types = {f["type"] for f in findings}
    assert "db_error" in types
    assert "status_change" in types
    assert "length_anomaly" in types


# ===================================================================
# OUTPUT REGION (command_output / sql_result_rows)
# ===================================================================

CMD_HEADER = "Here is the standard output of the command:<br>"
STDERR = "Here is the std err of the command (if any):<br>"

SQL_HEADER = "Your results are:<br>"


def test_command_output_fires_on_real_uid_leak():
    baseline = make_baseline(["<html>no cmd header here</html>"] * 5)
    a = DifferentialAnalyzer(baseline, "cmd_semicolon_id", ";id", "cmdi")
    body = (
        "<html><body><p>"
        + CMD_HEADER
        + "uid=0 gid=0(root) groups=0(root)<br><br>"
        + STDERR
        + "</p></body></html>"
    )
    findings = a.analyze(snap(text=body))
    types = [f["type"] for f in findings]
    assert "command_output" in types
    f = next(f for f in findings if f["type"] == "command_output")
    assert f["severity"] == "critical"
    assert "uid=0" in f["evidence"]


def test_command_output_does_not_fire_on_empty_region():
    baseline = make_baseline(["<html>plain</html>"] * 5)
    a = DifferentialAnalyzer(baseline, "cmd_semicolon_id", ";id", "cmdi")
    body = "<html><body><p>" + CMD_HEADER + "<br>" + STDERR + "</p></body></html>"
    findings = a.analyze(snap(text=body))
    assert "command_output" not in [f["type"] for f in findings]


def test_command_output_does_not_fire_when_baseline_has_content():
    dirty_baseline = (
        "<html><body><p>" + CMD_HEADER + "always present<br>" + STDERR + "</p></body></html>"
    )
    baseline = make_baseline([dirty_baseline] * 5)
    a = DifferentialAnalyzer(baseline, "cmd_semicolon_id", ";id", "cmdi")
    findings = a.analyze(snap(text=dirty_baseline))
    assert "command_output" not in [f["type"] for f in findings]


def test_command_output_does_not_fire_on_reflected_header():
    baseline = make_baseline(["<html>clean</html>"] * 5)
    payload = "x" + CMD_HEADER + "uid=0"
    a = DifferentialAnalyzer(baseline, "cmd_semicolon_id", payload, "cmdi")
    body = "<html><body>" + payload + "</body></html>"
    findings = a.analyze(snap(text=body))
    assert "command_output" not in [f["type"] for f in findings]


def test_sql_result_rows_fires_on_real_rows():
    baseline = make_baseline(["<html><body><p>Your results are:<br></p></body></html>"] * 5)
    a = DifferentialAnalyzer(baseline, "sql_or", "' OR '1'='1", "sqli")
    body = (
        "<html><body><p>Your results are:<br>"
        "0User01P455w0rd<br>1User02B3nchM3rk<br>2User03a$c11<br>3foobar<br>"
        "</p></body></html>"
    )
    findings = a.analyze(snap(text=body))
    types = [f["type"] for f in findings]
    assert "sql_result_rows" in types
    f = next(f for f in findings if f["type"] == "sql_result_rows")
    assert f["severity"] == "critical"
    assert "User01" in f["evidence"]


def test_sql_result_rows_does_not_fire_on_empty_region():
    baseline = make_baseline(["<html><body><p>Your results are:<br></p></body></html>"] * 5)
    a = DifferentialAnalyzer(baseline, "sql_or", "' OR '1'='1", "sqli")
    body = "<html><body><p>Your results are:<br></p></body></html>"
    findings = a.analyze(snap(text=body))
    assert "sql_result_rows" not in [f["type"] for f in findings]


def test_sql_result_rows_does_not_fire_when_baseline_has_rows():
    dirty = (
        "<html><body><p>Your results are:<br>0User01<br></p></body></html>"
    )
    baseline = make_baseline([dirty] * 5)
    a = DifferentialAnalyzer(baseline, "sql_or", "' OR '1'='1", "sqli")
    findings = a.analyze(snap(text=dirty))
    assert "sql_result_rows" not in [f["type"] for f in findings]


def test_output_region_ignores_clean_response():
    baseline = make_baseline(["<html>nothing</html>"] * 5)
    a = DifferentialAnalyzer(baseline, "sql_or", "' OR '1'='1", "sqli")
    findings = a.analyze(snap(text="<html>nothing</html>"))
    assert "command_output" not in [f["type"] for f in findings]
    assert "sql_result_rows" not in [f["type"] for f in findings]
