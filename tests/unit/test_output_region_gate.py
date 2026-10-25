"""Output-region oracle category-gating regression tests."""

from janissary.detection import Baseline, DifferentialAnalyzer, ResponseSnapshot


class _FakeResponse:
    def __init__(self, body, status=200):
        self.text = body
        self.status_code = status
        self.headers = {"content-type": "text/html"}
        self.elapsed = None


def _snap(body):
    return ResponseSnapshot.from_response(_FakeResponse(body))


def _baseline(bodies):
    b = Baseline()
    for body in bodies:
        b.add(_snap(body))
    return b


CLEAN = "<html>no output here</html>"
OUTPUT = (
    "<html>Here is the standard output of the command:<br>"
    "uid=0 gid=0(root)<br>"
    "Here is the std err of the command (if any):<br></html>"
)


def test_command_output_fires_on_cmdi_payload():
    a = DifferentialAnalyzer(
        baseline=_baseline([CLEAN] * 10),
        payload_name="cmdi_semicolon",
        payload_value="; id",
        payload_category="cmdi",
    )
    findings = a.analyze(_snap(OUTPUT))
    types = [f["type"] for f in findings]
    assert "command_output" in types


def test_command_output_silent_on_non_cmdi_payload():
    """A wildcard/traversal payload that triggers shell output on a
    cmdi path must not be reported as its own category."""
    a = DifferentialAnalyzer(
        baseline=_baseline([CLEAN] * 10),
        payload_name="ldap_wildcard",
        payload_value="*",
        payload_category="ldapi",
    )
    findings = a.analyze(_snap(OUTPUT))
    types = [f["type"] for f in findings]
    assert "command_output" not in types


def test_sql_result_rows_silent_on_non_sqli_payload():
    a = DifferentialAnalyzer(
        baseline=_baseline([CLEAN] * 10),
        payload_name="cmdi_semicolon",
        payload_value="; id",
        payload_category="cmdi",
    )
    sql_output = "<html>Your results are:<br>row1<br>row2<br></html>"
    findings = a.analyze(_snap(sql_output))
    types = [f["type"] for f in findings]
    assert "sql_result_rows" not in types
