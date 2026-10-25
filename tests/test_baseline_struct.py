"""Tests for engine/baseline_struct.py (Phase 1.3b, ADR-004).

Hand-built ResponseSnapshot fixtures. No Scanner, no network, no mocking
of anything except the snapshots themselves. Mirrors the style of
tests/test_dom_hash.py.
"""

from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError

import pytest

from janissary.detection import Baseline, ResponseSnapshot
from janissary.detection.analyzer import normalize_body
from janissary.engine.baseline_struct import (
    MAX_ARMING_HAMMING,
    MIN_ARMING_SAMPLES,
    ROOT_SIGNATURE_BYTES,
    ArmingReason,
    BaselineArmingState,
    compute_arming_state,
)
from janissary.engine.dom_hash import fingerprint as dom_fingerprint
from janissary.engine.dom_hash import hamming


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


def _snap(
    *,
    body: str,
    status: int = 200,
    content_type: str | None = "text/html",
    elapsed: float = 0.0,
) -> ResponseSnapshot:
    normalized = normalize_body(body)
    return ResponseSnapshot(
        status=status,
        body=body,
        normalized=normalized,
        fingerprint=hashlib.sha256(
            normalized.encode("utf-8", errors="ignore")
        ).hexdigest(),
        length=len(body),
        normalized_length=len(normalized),
        elapsed=elapsed,
        content_type=content_type if content_type is not None else "",
    )


def _same_skeleton(text: str) -> str:
    """Same tag structure, different text node."""
    return f"<html><body><div><p><span>{text}</span></p></div></body></html>"


# ---------------------------------------------------------------------------
# 1. Armed happy path
# ---------------------------------------------------------------------------


def test_armed_when_all_fingerprints_within_hamming_3():
    baseline = Baseline(
        snapshots=[
            _snap(body=_same_skeleton("alpha")),
            _snap(body=_same_skeleton("beta")),
            _snap(body=_same_skeleton("gamma")),
        ]
    )
    state = compute_arming_state(baseline)
    assert state.armed is True
    assert state.reason == ArmingReason.ARMED
    assert state.sample_count == 3
    assert state.hamming_max <= MAX_ARMING_HAMMING


# ---------------------------------------------------------------------------
# 2. No HTML samples at all
# ---------------------------------------------------------------------------


def test_unarmed_when_no_html_samples():
    baseline = Baseline()  # empty snapshots list
    state = compute_arming_state(baseline)
    assert state.armed is False
    assert state.reason == ArmingReason.UNARMED_NO_HTML_SAMPLES
    assert state.fingerprints == ()
    assert state.root_signature is None
    assert state.sample_count == 0
    assert state.hamming_max == 0


# ---------------------------------------------------------------------------
# 3. Non-HTML content types only
# ---------------------------------------------------------------------------


def test_unarmed_when_content_type_not_html():
    baseline = Baseline(
        snapshots=[
            _snap(body='{"a":1}', content_type="application/json"),
            _snap(body='{"b":2}', content_type="application/json"),
            _snap(body="hello", content_type="text/plain"),
        ]
    )
    state = compute_arming_state(baseline)
    assert state.armed is False
    assert state.reason == ArmingReason.UNARMED_NO_HTML_SAMPLES
    assert state.sample_count == 0


# ---------------------------------------------------------------------------
# 4. All skeletons empty (only ignored tags)
# ---------------------------------------------------------------------------


def test_unarmed_when_all_skeletons_empty():
    # script is in IGNORED_TAGS; no non-ignored tags => shingle_count == 0.
    baseline = Baseline(
        snapshots=[
            _snap(body="<script>var a = 1;</script>"),
            _snap(body="<script>var b = 2;</script>"),
            _snap(body="<script>var c = 3;</script>"),
        ]
    )
    state = compute_arming_state(baseline)
    assert state.armed is False
    assert state.reason == ArmingReason.UNARMED_EMPTY_SKELETON
    assert state.sample_count == 3


# ---------------------------------------------------------------------------
# 5. Insufficient samples
# ---------------------------------------------------------------------------


def test_unarmed_when_insufficient_samples():
    baseline = Baseline(
        snapshots=[
            _snap(body=_same_skeleton("alpha")),
            _snap(body=_same_skeleton("beta")),
        ]
    )
    state = compute_arming_state(baseline)
    assert state.armed is False
    assert state.reason == ArmingReason.UNARMED_INSUFFICIENT_SAMPLES
    assert state.sample_count == 2


# ---------------------------------------------------------------------------
# 6. Dispersion above threshold
# ---------------------------------------------------------------------------


def test_unarmed_when_dispersion_exceeds_max():
    bodies = [
        "<html><body><div><p><span><em>a</em></span></p></div></body></html>",
        "<html><body><table><tr><td><th>b</th></td></tr></table></body></html>",
        "<html><body><section><article><header>c</header></article></section></body></html>",
    ]
    # Precondition: the fixture really is dispersed beyond the threshold.
    fps = [dom_fingerprint(b).value for b in bodies]
    expected_max = max(
        hamming(fps[i], fps[j]) for i in range(3) for j in range(i + 1, 3)
    )
    assert expected_max > MAX_ARMING_HAMMING

    state = compute_arming_state(Baseline(snapshots=[_snap(body=b) for b in bodies]))
    assert state.armed is False
    assert state.reason == ArmingReason.UNARMED_DISPERSION
    assert state.hamming_max == expected_max


# ---------------------------------------------------------------------------
# 7. Root signature definition (truncation)
# ---------------------------------------------------------------------------


def test_root_signature_is_sha256_of_first_4096_bytes_of_normalized_body():
    long_text = "x" * 5000
    body = (
        "<html><body><div><section><p><span>"
        + long_text
        + "</span></p></section></div></body></html>"
    )

    normalized = normalize_body(body)
    normalized_bytes = normalized.encode("utf-8", errors="ignore")
    # Precondition: the fixture is large enough that truncation is meaningful.
    assert len(normalized_bytes) > ROOT_SIGNATURE_BYTES

    full = hashlib.sha256(normalized_bytes).hexdigest()
    truncated = hashlib.sha256(normalized_bytes[:ROOT_SIGNATURE_BYTES]).hexdigest()
    assert full != truncated  # precondition

    state = compute_arming_state(
        Baseline(snapshots=[_snap(body=body), _snap(body=body), _snap(body=body)])
    )
    assert state.armed is True
    assert state.root_signature == truncated
    assert state.root_signature != full


# ---------------------------------------------------------------------------
# 8. Armed with root signature when bodies stable
# ---------------------------------------------------------------------------


def test_armed_with_root_signature_when_bodies_stable():
    body = "<html><body><div><p>stable</p></div></body></html>"
    baseline = Baseline(snapshots=[_snap(body=body) for _ in range(3)])
    state = compute_arming_state(baseline)
    assert state.armed is True
    assert state.root_signature is not None
    assert len(state.root_signature) == 64  # sha256 hex digest length


# ---------------------------------------------------------------------------
# 9. Armed WITHOUT root signature when text unstable, structure stable
# ---------------------------------------------------------------------------


def test_armed_without_root_signature_when_all_bodies_distinct_but_structurally_close():
    baseline = Baseline(
        snapshots=[
            _snap(body=_same_skeleton("alpha")),
            _snap(body=_same_skeleton("beta")),
            _snap(body=_same_skeleton("gamma")),
        ]
    )
    # Precondition: text is genuinely distinct (different .fingerprint values).
    fps = {s.fingerprint for s in baseline.snapshots}
    assert len(fps) == 3

    state = compute_arming_state(baseline)
    assert state.armed is True
    assert state.reason == ArmingReason.ARMED
    assert state.root_signature is None


# ---------------------------------------------------------------------------
# 10. Root signature changes when a reflected value changes
# ---------------------------------------------------------------------------


def test_root_signature_changes_when_reflected_value_changes():
    body_a = "<html><body><div><p>Reflected: Alice</p></div></body></html>"
    body_b = "<html><body><div><p>Reflected: Bob</p></div></body></html>"

    # Both stable baselines: 3 identical copies each.
    state_a = compute_arming_state(
        Baseline(snapshots=[_snap(body=body_a) for _ in range(3)])
    )
    state_b = compute_arming_state(
        Baseline(snapshots=[_snap(body=body_b) for _ in range(3)])
    )
    assert state_a.root_signature is not None
    assert state_b.root_signature is not None
    assert state_a.root_signature != state_b.root_signature, (
        "normalize_body must preserve reflected text — see ADR-004 §D3. "
        "If this fails, 1.3c's discard path is unsafe."
    )


# ---------------------------------------------------------------------------
# 11. hamming_max reflects actual pairwise maximum
# ---------------------------------------------------------------------------


def test_hamming_max_reflects_max_pairwise_distance():
    # Identical structure => 0.
    identical = [
        _snap(body=_same_skeleton("alpha")),
        _snap(body=_same_skeleton("beta")),
        _snap(body=_same_skeleton("gamma")),
    ]
    state = compute_arming_state(Baseline(snapshots=identical))
    assert state.hamming_max == 0

    # Structurally distinct => > 0.
    distinct_bodies = [
        "<html><body><div><p>a</p></div></body></html>",
        "<html><body><section><article>b</article></section></body></html>",
        "<html><body><table><tr><td>c</td></tr></table></body></html>",
    ]
    fps = [dom_fingerprint(b).value for b in distinct_bodies]
    expected = max(hamming(fps[i], fps[j]) for i in range(3) for j in range(i + 1, 3))
    state = compute_arming_state(
        Baseline(snapshots=[_snap(body=b) for b in distinct_bodies])
    )
    assert state.hamming_max == expected


# ---------------------------------------------------------------------------
# 12. Empty baseline does not raise
# ---------------------------------------------------------------------------


def test_compute_arming_state_does_not_raise_on_empty_baseline():
    # Smoke test — the function is pure and must not raise on a bare Baseline().
    state = compute_arming_state(Baseline())
    assert isinstance(state, BaselineArmingState)


# ---------------------------------------------------------------------------
# 13. Reason precedence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("case", "snapshots", "expected_reason", "expected_sample_count"),
    [
        (
            "no_html_beats_insufficient",
            [
                _snap(body="<html><body>hi</body></html>", content_type="text/plain"),
                _snap(
                    body="<html><body>there</body></html>", content_type="text/plain"
                ),
            ],
            ArmingReason.UNARMED_NO_HTML_SAMPLES,
            0,
        ),
        (
            "insufficient_beats_empty_skeleton",
            [
                _snap(body="<script>alert(1)</script>"),  # empty skeleton
                _snap(body=_same_skeleton("alpha")),
            ],
            ArmingReason.UNARMED_INSUFFICIENT_SAMPLES,
            2,
        ),
        (
            "empty_skeleton_beats_dispersion",
            [
                _snap(body="<script>alert(1)</script>"),  # empty skeleton
                _snap(body="<html><body><div><p>a</p></div></body></html>"),
                _snap(
                    body="<html><body><table><tr><td>b</td></tr></table></body></html>"
                ),
            ],
            ArmingReason.UNARMED_EMPTY_SKELETON,
            3,
        ),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_reason_precedence(case, snapshots, expected_reason, expected_sample_count):
    state = compute_arming_state(Baseline(snapshots=snapshots))
    assert state.armed is False
    assert state.reason == expected_reason, case
    assert state.sample_count == expected_sample_count, case


# ---------------------------------------------------------------------------
# 14. Frozen state
# ---------------------------------------------------------------------------


def test_armed_state_is_frozen():
    state = compute_arming_state(
        Baseline(snapshots=[_snap(body=_same_skeleton("a")) for _ in range(3)])
    )
    with pytest.raises(FrozenInstanceError):
        state.armed = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 15. hamming_max is 0 with fewer than two samples
# ---------------------------------------------------------------------------


def test_hamming_max_zero_when_one_or_zero_samples():
    zero = compute_arming_state(Baseline())
    assert zero.hamming_max == 0

    one = compute_arming_state(Baseline(snapshots=[_snap(body=_same_skeleton("a"))]))
    assert one.hamming_max == 0
    assert one.sample_count == 1
    assert one.reason == ArmingReason.UNARMED_INSUFFICIENT_SAMPLES
