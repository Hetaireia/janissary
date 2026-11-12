"""M81a: baseline-aware heuristic suppression (matching only)."""

from janissary.heuristic.engine import HeuristicEngine
from janissary.heuristic.signatures import HeuristicSignature
from janissary.heuristic.types import (
    OBSERVATION_FIXTURE_ALLOWED_FIELDS,
    Observation,
)


def _sig(
    *,
    sig_id="test_sig",
    layer="body",
    patterns=(r"SQL syntax error",),
    category="sqli",
):
    return HeuristicSignature(
        id=sig_id,
        category=category,
        target_layer=layer,
        patterns=patterns,
        base_confidence=0.5,
    )


def _obs(
    body="",
    *,
    is_baseline=False,
    headers=None,
    param="q",
    payload_name="p",
    payload_value="v",
    url="http://x/a",
):
    return Observation(
        url=url,
        body=body,
        headers=headers or {},
        method="GET",
        param=param,
        payload_name=payload_name,
        payload_value=payload_value,
        is_baseline=is_baseline,
    )


# --- backward compatibility ---


def test_observation_is_baseline_default_false():
    assert Observation(url="u", body="b").is_baseline is False


def test_fixture_allowed_fields_includes_is_baseline():
    assert "is_baseline" in OBSERVATION_FIXTURE_ALLOWED_FIELDS


def test_no_baseline_behaves_as_before():
    eng = HeuristicEngine(signatures=(_sig(),))
    payload = _obs("SQL syntax error at line 1")
    matches = eng.match([payload])
    assert len(matches) == 1
    m = matches[0]
    assert m.suppressed is False
    assert m.suppression_reason == ""
    assert m.suppressed_by_observation_index is None
    assert eng.suppressed_count == 0


# --- suppression core ---


def test_baseline_match_suppresses_payload_match():
    eng = HeuristicEngine(signatures=(_sig(),))
    baseline = _obs("SQL syntax error at line 1", is_baseline=True)
    payload = _obs("SQL syntax error at line 5")
    matches = eng.match([baseline, payload])
    assert len(matches) == 1
    m = matches[0]
    assert m.suppressed is True
    assert m.suppression_reason == "baseline_match"
    assert m.suppressed_by_observation_index == 0
    assert eng.suppressed_count == 1


def test_baseline_never_returned_as_finding():
    eng = HeuristicEngine(signatures=(_sig(),))
    baseline = _obs("SQL syntax error", is_baseline=True)
    matches = eng.match([baseline])
    assert matches == []


def test_payload_not_suppressed_when_baseline_absent():
    eng = HeuristicEngine(signatures=(_sig(),))
    payload = _obs("SQL syntax error")
    matches = eng.match([payload])
    assert len(matches) == 1
    assert matches[0].suppressed is False


def test_different_pattern_does_not_suppress():
    sig = _sig(patterns=(r"SQL syntax error", r"Warning: mysql_"))
    eng = HeuristicEngine(signatures=(sig,))
    baseline = _obs("Warning: mysql_ something", is_baseline=True)
    payload = _obs("SQL syntax error")
    matches = eng.match([baseline, payload])
    assert len(matches) == 1
    assert matches[0].suppressed is False


# --- strict-triple safeguard ---


def test_same_sig_id_across_layers_does_not_cross_suppress():
    """Strict triple includes target_layer: baseline in headers must not
    suppress payload in body even with matching sig_id and pattern."""
    body_sig = _sig(sig_id="shared", layer="body")
    header_sig = _sig(sig_id="shared", layer="headers")
    eng = HeuristicEngine(signatures=(body_sig, header_sig))
    baseline = _obs("", is_baseline=True, headers={"X": "SQL syntax error"})
    payload = _obs("SQL syntax error")
    matches = eng.match([baseline, payload])
    body_matches = [m for m in matches if m.target_layer == "body"]
    header_matches = [m for m in matches if m.target_layer == "headers"]
    assert len(body_matches) == 1
    assert body_matches[0].suppressed is False
    assert len(header_matches) == 0


# --- determinism ---


def test_multiple_baselines_first_index_recorded():
    eng = HeuristicEngine(signatures=(_sig(),))
    b1 = _obs("SQL syntax error", is_baseline=True)
    b2 = _obs("SQL syntax error", is_baseline=True)
    payload = _obs("SQL syntax error")
    matches = eng.match([b1, b2, payload])
    assert len(matches) == 1
    assert matches[0].suppressed_by_observation_index == 0


def test_suppressed_by_observation_index_in_original_sequence():
    eng = HeuristicEngine(signatures=(_sig(),))
    payload = _obs("SQL syntax error")
    baseline = _obs("SQL syntax error", is_baseline=True)
    matches = eng.match([payload, baseline])
    assert len(matches) == 1
    assert matches[0].observation_index == 0
    assert matches[0].suppressed_by_observation_index == 1


# --- count semantics ---


def test_suppressed_count_resets_per_call():
    eng = HeuristicEngine(signatures=(_sig(),))
    b = _obs("SQL syntax error", is_baseline=True)
    p = _obs("SQL syntax error")
    eng.match([b, p])
    assert eng.suppressed_count == 1
    eng.match([p])
    assert eng.suppressed_count == 0


def test_suppressed_count_counts_only_suppressed_payload_matches():
    sig_a = _sig(sig_id="a", patterns=(r"alpha",))
    sig_b = _sig(sig_id="b", patterns=(r"beta",), category="xss")
    eng = HeuristicEngine(signatures=(sig_a, sig_b))
    baseline = _obs("alpha present", is_baseline=True)
    payload = _obs("alpha and beta present")
    eng.match([baseline, payload])
    assert eng.suppressed_count == 1


# --- candidates ---


def test_to_candidates_excludes_suppressed_by_default():
    eng = HeuristicEngine(signatures=(_sig(),))
    b = _obs("SQL syntax error", is_baseline=True)
    p = _obs("SQL syntax error")
    matches = eng.match([b, p])
    cands = eng.to_candidates(matches, [b, p])
    assert len(cands) == 0


def test_to_candidates_include_suppressed_emits_them_with_marker():
    eng = HeuristicEngine(signatures=(_sig(),))
    b = _obs("SQL syntax error", is_baseline=True)
    p = _obs("SQL syntax error")
    matches = eng.match([b, p])
    cands = eng.to_candidates(matches, [b, p], include_suppressed=True)
    assert len(cands) == 1
    assert cands[0].detail.startswith("[suppressed: baseline_match]")


def test_to_candidates_mixed_returns_only_unsuppressed():
    sig_a = _sig(sig_id="a", patterns=(r"alpha",))
    sig_b = _sig(sig_id="b", patterns=(r"beta",), category="xss")
    eng = HeuristicEngine(signatures=(sig_a, sig_b))
    baseline = _obs("alpha present", is_baseline=True)
    payload = _obs("alpha and beta present")
    matches = eng.match([baseline, payload])
    cands = eng.to_candidates(matches, [baseline, payload])
    assert len(cands) == 1
    assert "beta" in cands[0].detail
