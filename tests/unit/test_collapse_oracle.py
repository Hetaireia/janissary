"""Unit tests for the traversal collapse oracle (ADR-006)."""

from __future__ import annotations

from pathlib import Path

from janissary.detection import Baseline, ResponseSnapshot
from janissary.detection.collapse_oracle import (
    MAX_COLLAPSE_DIST,
    check_traversal_collapse_oracle,
)
from janissary.engine.baseline_struct import ArmingReason, BaselineArmingState
from janissary.engine.dom_hash import fingerprint

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
REAL_FORM = (FIXTURES / "real_html_form.html").read_text(encoding="utf-8")
PASSWD = (FIXTURES / "etc_passwd.txt").read_text(encoding="utf-8")
MINIMAL = "<html><body>hello</body></html>"


def _snap(
    body: str, status: int = 200, content_type: str = "text/html"
) -> ResponseSnapshot:
    return ResponseSnapshot(
        status=status,
        body=body,
        normalized=body,
        fingerprint=body,
        length=len(body),
        normalized_length=len(body),
        elapsed=0.01,
        content_type=content_type,
    )


def _baseline_of(body: str, count: int = 3) -> Baseline:
    b = Baseline()
    for _ in range(count):
        b.add(_snap(body))
    return b


def _arming(fingerprints: tuple[int, ...], armed: bool = True) -> BaselineArmingState:
    return BaselineArmingState(
        armed=armed,
        reason=ArmingReason.ARMED if armed else ArmingReason.UNARMED_DISPERSION,
        fingerprints=fingerprints,
        root_signature=None,
        sample_count=len(fingerprints),
        hamming_max=0,
    )


def _fp_vals(body: str, count: int = 3) -> tuple[int, ...]:
    return tuple(fingerprint(body).value for _ in range(count))


# -------------------- truth table --------------------


def test_unarmed_never_emits():
    baseline = _baseline_of(REAL_FORM)
    arming = _arming(_fp_vals(REAL_FORM), armed=False)
    snap = _snap(PASSWD, status=200, content_type="text/plain")
    out = check_traversal_collapse_oracle(
        baseline=baseline,
        arming=arming,
        snapshot=snap,
        response_status=200,
        payload_value="../../../etc/passwd",
        payload_name="traversal_passwd",
    )
    assert out == []


def test_distance_below_threshold_no_emit():
    baseline = _baseline_of(REAL_FORM)
    arming = _arming((fingerprint(MINIMAL).value,))
    # payload is MINIMAL itself: dist 0, no aux
    snap = _snap(MINIMAL)
    out = check_traversal_collapse_oracle(
        baseline=baseline,
        arming=arming,
        snapshot=snap,
        response_status=200,
        payload_value="x",
        payload_name="traversal_passwd",
    )
    assert out == []


def test_distance_above_threshold_no_aux_no_emit():
    baseline = _baseline_of(REAL_FORM)
    arming = _arming(_fp_vals(REAL_FORM))
    # real form echoed back: dist 0 to itself, no aux
    snap = _snap(REAL_FORM)
    out = check_traversal_collapse_oracle(
        baseline=baseline,
        arming=arming,
        snapshot=snap,
        response_status=200,
        payload_value="x",
        payload_name="traversal_passwd",
    )
    assert out == []


def test_passwd_emits_no_markup():
    baseline = _baseline_of(REAL_FORM)
    arming = _arming(_fp_vals(REAL_FORM))
    snap = _snap(PASSWD, status=200, content_type="text/plain")
    out = check_traversal_collapse_oracle(
        baseline=baseline,
        arming=arming,
        snapshot=snap,
        response_status=200,
        payload_value="../../../etc/passwd",
        payload_name="traversal_passwd",
    )
    assert len(out) == 1
    assert out[0]["type"] == "traversal_collapse"
    assert out[0]["category"] == "traversal"
    assert out[0]["severity"] == "critical"
    assert "collapse_no_markup" in out[0]["aux_signals"]
    assert (
        out[0]["min_distance"] is not None
        and out[0]["min_distance"] > MAX_COLLAPSE_DIST
    )


def test_tiny_body_emits_when_short_and_has_content():
    baseline = _baseline_of(REAL_FORM)  # ~500B mean
    arming = _arming(_fp_vals(REAL_FORM))
    small_with_path = "<html><body>/var/www</body></html>"  # 34B, <10% of 500
    # Wait: this has "<", so no_markup doesn't fire; but tiny fires via "/" check
    snap = _snap(small_with_path)
    out = check_traversal_collapse_oracle(
        baseline=baseline,
        arming=arming,
        snapshot=snap,
        response_status=200,
        payload_value="x",
        payload_name="traversal_passwd",
    )
    assert len(out) == 1
    assert "collapse_tiny_body" in out[0]["aux_signals"]


def test_tiny_body_does_not_emit_on_generic_500():
    baseline = _baseline_of(REAL_FORM)
    arming = _arming(_fp_vals(REAL_FORM))
    snap = _snap("Internal Server Error", status=500)
    out = check_traversal_collapse_oracle(
        baseline=baseline,
        arming=arming,
        snapshot=snap,
        response_status=500,
        payload_value="x",
        payload_name="traversal_passwd",
    )
    assert out == []


def test_tiny_body_does_not_emit_without_content_shape():
    baseline = _baseline_of(REAL_FORM)
    arming = _arming(_fp_vals(REAL_FORM))
    # Short, 200 status, no "<", no ":", no "/" — anti-FP guard
    snap = _snap("blocked by waf", status=200)
    out = check_traversal_collapse_oracle(
        baseline=baseline,
        arming=arming,
        snapshot=snap,
        response_status=200,
        payload_value="x",
        payload_name="traversal_passwd",
    )
    assert out == []


def test_no_markup_requires_marker():
    baseline = _baseline_of(REAL_FORM)
    arming = _arming(_fp_vals(REAL_FORM))
    # No "<" but no marker either
    snap = _snap("just some plain text here", status=200)
    out = check_traversal_collapse_oracle(
        baseline=baseline,
        arming=arming,
        snapshot=snap,
        response_status=200,
        payload_value="x",
        payload_name="traversal_passwd",
    )
    assert out == []


def test_reason_priority_no_markup_over_known_file():
    baseline = _baseline_of(REAL_FORM)
    arming = _arming(_fp_vals(REAL_FORM))
    # passwd triggers both no_markup and known_file; priority is no_markup
    snap = _snap(PASSWD, status=200, content_type="text/plain")
    out = check_traversal_collapse_oracle(
        baseline=baseline,
        arming=arming,
        snapshot=snap,
        response_status=200,
        payload_value="../../../etc/passwd",
        payload_name="traversal_passwd",
    )
    assert out[0]["reason"] == "collapse_no_markup"
