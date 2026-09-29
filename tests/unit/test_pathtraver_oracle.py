"""Unit tests for the pathtraver existence-oracle detector.

The oracle is a paired differential: response A on an existing path
and response B on a guaranteed-nonexistent path must diverge on the
existence-signal strings. Same signal on both, no signal, or both
signals on one side, is not evidence.

Negative tests are the point.
"""

from janissary.detection import Baseline, ResponseSnapshot
from janissary.detection.analyzer import check_pathtraver_oracle


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


EXISTS_BODY = (
    "Access to file: ../../../../etc/passwd created."
    " And file already exists."
)
NOEXIST_BODY = (
    "Access to file: ../../../../etc/passwd_janissary_noexist_abc123 created."
    " But file doesn't exist yet."
)
BENIGN = "Access to file: created."

PAYLOAD_EXISTS = "../../../etc/passwd"
PAYLOAD_NOEXIST = "../../../etc/passwd_janissary_noexist_abc123"


def _call(baseline, a, b, pa=PAYLOAD_EXISTS, pb=PAYLOAD_NOEXIST):
    return check_pathtraver_oracle(
        baseline=baseline,
        snapshot_exists=a,
        snapshot_noexist=b,
        payload_exists=pa,
        payload_noexist=pb,
    )


def test_fires_on_divergent_existence():
    baseline = make_baseline([BENIGN])
    findings = _call(baseline, snap(text=EXISTS_BODY), snap(text=NOEXIST_BODY))
    assert len(findings) == 1
    assert findings[0]["type"] == "pathtraver_existence_oracle"
    assert findings[0]["severity"] == "critical"


def test_fires_reverse_direction():
    baseline = make_baseline([BENIGN])
    findings = _call(baseline, snap(text=NOEXIST_BODY), snap(text=EXISTS_BODY))
    assert len(findings) == 1


def test_case_insensitive():
    baseline = make_baseline([BENIGN])
    findings = _call(
        baseline,
        snap(text="Access created. And FILE ALREADY EXISTS."),
        snap(text="But file DOESN'T EXIST YET."),
    )
    assert len(findings) == 1


def test_accepts_does_not_variant():
    baseline = make_baseline([BENIGN])
    findings = _call(
        baseline,
        snap(text=EXISTS_BODY),
        snap(text="But file does not exist yet."),
    )
    assert len(findings) == 1


def test_silent_when_both_say_exists():
    baseline = make_baseline([BENIGN])
    findings = _call(baseline, snap(text=EXISTS_BODY), snap(text=EXISTS_BODY))
    assert findings == []


def test_silent_when_both_say_noexist():
    baseline = make_baseline([BENIGN])
    findings = _call(baseline, snap(text=NOEXIST_BODY), snap(text=NOEXIST_BODY))
    assert findings == []


def test_silent_when_no_signal_present():
    baseline = make_baseline([BENIGN])
    findings = _call(baseline, snap(text=BENIGN), snap(text=BENIGN))
    assert findings == []


def test_silent_when_one_signal_missing():
    baseline = make_baseline([BENIGN])
    findings = _call(baseline, snap(text=EXISTS_BODY), snap(text=BENIGN))
    assert findings == []


def test_silent_when_both_signals_on_one_response():
    baseline = make_baseline([BENIGN])
    both = EXISTS_BODY + " " + NOEXIST_BODY
    findings = _call(baseline, snap(text=both), snap(text=BENIGN))
    assert findings == []


def test_silent_when_baseline_dirty():
    baseline = make_baseline([EXISTS_BODY])
    findings = _call(baseline, snap(text=EXISTS_BODY), snap(text=NOEXIST_BODY))
    assert findings == []


def test_silent_when_payload_echoes_oracle():
    baseline = make_baseline([BENIGN])
    findings = _call(
        baseline,
        snap(text=EXISTS_BODY),
        snap(text=NOEXIST_BODY),
        pa="file already exists",
        pb=PAYLOAD_NOEXIST,
    )
    assert findings == []


def test_fires_when_baseline_reports_noexist():
    """The app's benign default is 'file doesn't exist yet'. That is
    the control state, not baseline poison. Only an EXISTS string in
    the baseline invalidates the oracle."""
    baseline = make_baseline([NOEXIST_BODY, NOEXIST_BODY])
    findings = _call(baseline, snap(text=EXISTS_BODY), snap(text=NOEXIST_BODY))
    assert len(findings) == 1
