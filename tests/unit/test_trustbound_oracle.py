"""Unit tests for the trustbound session-sink oracle.

Vulnerable trustbound cases echo the *injected* value into a session
message ("... saved in session."); non-vulnerable cases emit the same
phrase with a hardcoded benign value. So the phrase alone is not
diagnostic, and the injected marker alone is not diagnostic either
(crypto/hash/xss also reflect). Both together: measured 54 TP / 0 FP.

Negative tests are the point.
"""

from janissary.detection import Baseline, ResponseSnapshot
from janissary.detection.analyzer import check_trustbound_oracle


class FakeResponse:
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
    return ResponseSnapshot.from_response(FakeResponse(**kwargs))


def make_baseline(bodies):
    b = Baseline()
    for body in bodies:
        b.add(snap(text=body))
    return b


MARKER = "JNSRY_TB_abc123def456"
BENIGN = "Welcome."

VULN_BODY = (
    "Item: 'userid' with value: '" + MARKER + "' saved in session.\n"
)
NONV_BODY = (
    "Item: 'userid' with value: 'moresafe' saved in session.\n"
)
REFLECT_NO_SINK = "Sensitive value: '" + MARKER + "' encrypted and stored\n"
SINK_NO_MARKER = "Item: 'userid' with value: 'This_should_always_happen' saved in session.\n"


def test_fires_on_marker_and_sink():
    baseline = make_baseline([BENIGN])
    findings = check_trustbound_oracle(baseline, snap(text=VULN_BODY), MARKER)
    assert len(findings) == 1
    assert findings[0]["type"] == "trustbound_session_oracle"
    assert findings[0]["severity"] == "high"


def test_silent_on_phrase_without_marker():
    # Non-vuln shape: sink phrase with a hardcoded benign value.
    baseline = make_baseline([BENIGN])
    assert check_trustbound_oracle(baseline, snap(text=NONV_BODY), MARKER) == []


def test_silent_on_marker_without_sink():
    # Crypto/hash shape: marker reflected, but no session sink.
    baseline = make_baseline([BENIGN])
    assert check_trustbound_oracle(baseline, snap(text=REFLECT_NO_SINK), MARKER) == []


def test_silent_on_sink_without_marker_from_injection():
    baseline = make_baseline([BENIGN])
    assert check_trustbound_oracle(baseline, snap(text=SINK_NO_MARKER), MARKER) == []


def test_silent_when_marker_in_baseline():
    # Unconditional echo: baseline already carries the marker.
    baseline = make_baseline([VULN_BODY])
    assert check_trustbound_oracle(baseline, snap(text=VULN_BODY), MARKER) == []


def test_silent_on_empty_marker():
    baseline = make_baseline([BENIGN])
    assert check_trustbound_oracle(baseline, snap(text=VULN_BODY), "") == []


def test_case_insensitive_sink():
    baseline = make_baseline([BENIGN])
    body = "Item: 'userid' with value: '" + MARKER + "' SAVED IN SESSION."
    findings = check_trustbound_oracle(baseline, snap(text=body), MARKER)
    assert len(findings) == 1
