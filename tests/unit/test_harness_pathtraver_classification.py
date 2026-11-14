"""M83 Stage 1: classification derivation tests.

Covers criterion 3 (four reachable classes producible from fixtures),
criterion 4 (distinctive_content never emitted), criterion 8 (R2a strict
inconclusive), and criterion 9 (R3a leakage with diagnostic).

Assertions run the real check_pathtraver_oracle so that classification
derivation is tested against actual oracle outcomes, not against a mock.
"""

import inspect

from janissary.detection import Baseline, ResponseSnapshot
from janissary.detection.analyzer import check_pathtraver_oracle
from janissary.harness import pathtraver
from janissary.harness.pathtraver import _derive_classification


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


BENIGN = "Access to file: created."
EXISTS_BODY = "Access to file: passwd created. And file already exists."
NOEXIST_BODY = "Access to file: passwd_noexist created. But file doesn't exist yet."
PAYLOAD_EXISTS = "../../../etc/passwd"
PAYLOAD_NOEXIST = "../../../etc/passwd_janissary_noexist_abc123"


def _classify(baseline, snap_e, snap_n, pe=PAYLOAD_EXISTS, pn=PAYLOAD_NOEXIST):
    oracle_result = check_pathtraver_oracle(
        baseline=baseline,
        snapshot_exists=snap_e,
        snapshot_noexist=snap_n,
        payload_exists=pe,
        payload_noexist=pn,
    )
    classification, reason = _derive_classification(
        baseline=baseline,
        snapshot_exists=snap_e,
        snapshot_noexist=snap_n,
        payload_exists=pe,
        payload_noexist=pn,
        oracle_result=oracle_result,
    )
    return classification, reason, oracle_result


def test_criterion_3_existence_divergence():
    baseline = make_baseline([BENIGN])
    snap_e = snap(text=EXISTS_BODY)
    snap_n = snap(text=NOEXIST_BODY)
    classification, _reason, oracle_result = _classify(baseline, snap_e, snap_n)
    assert len(oracle_result) > 0, "oracle must fire on divergent bodies"
    assert classification == "existence_divergence"


def test_criterion_3_no_observable_divergence():
    baseline = make_baseline([BENIGN])
    snap_e = snap(text="file already exists")
    snap_n = snap(text="file already exists")
    classification, reason, oracle_result = _classify(baseline, snap_e, snap_n)
    assert oracle_result == [], "oracle must not fire on identical signals"
    assert classification == "no_observable_divergence"
    assert "both probes reported" in reason


def test_criterion_3_inconclusive_via_payload_leakage():
    baseline = make_baseline([BENIGN])
    snap_e = snap(text=BENIGN)
    snap_n = snap(text=BENIGN)
    classification, reason, oracle_result = _classify(
        baseline, snap_e, snap_n, pe="payload with file already exists"
    )
    assert oracle_result == []
    assert classification == "inconclusive"
    assert "payload leakage" in reason


def test_criterion_3_inconclusive_via_baseline_poison():
    baseline = make_baseline(["file already exists"])
    snap_e = snap(text=BENIGN)
    snap_n = snap(text=BENIGN)
    classification, reason, oracle_result = _classify(baseline, snap_e, snap_n)
    assert oracle_result == []
    assert classification == "inconclusive"
    assert "baseline poisoned" in reason


def test_criterion_3_inconclusive_via_signal_extraction_failed_exists():
    baseline = make_baseline([BENIGN])
    snap_e = snap(text="nothing interesting here")
    snap_n = snap(text=NOEXIST_BODY)
    classification, reason, oracle_result = _classify(baseline, snap_e, snap_n)
    assert oracle_result == []
    assert classification == "inconclusive"
    assert "signal extraction failed: exists probe" in reason


def test_criterion_3_inconclusive_via_signal_extraction_failed_noexist():
    baseline = make_baseline([BENIGN])
    snap_e = snap(text=EXISTS_BODY)
    snap_n = snap(text="nothing interesting here")
    classification, reason, oracle_result = _classify(baseline, snap_e, snap_n)
    assert oracle_result == []
    assert classification == "inconclusive"
    assert "signal extraction failed: noexist probe" in reason


def test_criterion_4_distinctive_content_never_emitted():
    source = inspect.getsource(pathtraver._derive_classification)
    assert "distinctive_content" not in source


def test_criterion_8_r2a_ambiguous_classifies_inconclusive():
    baseline = make_baseline([BENIGN])
    snap_e = snap(text="file already exists and file doesn't exist yet")
    snap_n = snap(text=NOEXIST_BODY)
    classification, _reason, _oracle = _classify(baseline, snap_e, snap_n)
    assert classification == "inconclusive"


def test_criterion_9_r3a_leakage_with_diagnostic():
    baseline = make_baseline([BENIGN])
    snap_e = snap(text=BENIGN)
    snap_n = snap(text=BENIGN)
    classification, reason, _oracle = _classify(
        baseline, snap_e, snap_n, pn="payload file doesn't exist yet"
    )
    assert classification == "inconclusive"
    assert "payload leakage" in reason


def test_helpers_imported_from_analyzer():
    source = inspect.getsource(pathtraver._derive_classification)
    assert "analyzer._PATHTRAVER_EXISTS" in source
    assert "analyzer._PATHTRAVER_NOEXIST" in source
    assert "analyzer._pathtraver_signal" in source


def test_payload_leakage_and_baseline_poison_precedence():
    # Baseline poisoned AND payload contains exists-pattern.
    # Payload leakage (branch 2) must win over baseline poison (branch 3).
    baseline = make_baseline(["file already exists"])
    snap_e = snap(text=BENIGN)
    snap_n = snap(text=BENIGN)
    classification, reason, oracle_result = _classify(
        baseline, snap_e, snap_n, pe="payload with file already exists"
    )
    assert oracle_result == []
    assert classification == "inconclusive"
    assert "payload leakage" in reason
