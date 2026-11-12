"""M82b: candidate integration for MatchGroup aggregation."""

from janissary.heuristic.engine import (
    HeuristicEngine,
    HeuristicMatch,
)
from janissary.heuristic.types import Observation


def _obs(
    *,
    url="http://x/a",
    method="GET",
    param="q",
    body="MARK",
    payload_name="p1",
    payload_value="v1",
    observation_id="oid-1",
    is_baseline=False,
):
    return Observation(
        url=url,
        body=body,
        method=method,
        param=param,
        payload_name=payload_name,
        payload_value=payload_value,
        observation_id=observation_id,
        is_baseline=is_baseline,
    )


def _match(
    *,
    sig_id="SIG-1",
    category="cat:a",
    obs_idx=0,
    confidence=0.5,
    matched_pattern=r"MARK",
    evidence="MARK",
    suppressed=False,
):
    return HeuristicMatch(
        signature_id=sig_id,
        category=category,
        target_layer="body",
        matched_pattern=matched_pattern,
        evidence_excerpt=evidence,
        confidence=confidence,
        observation_index=obs_idx,
        suppressed=suppressed,
        suppression_reason="baseline_match" if suppressed else "",
        suppressed_by_observation_index=None,
    )


# --- backward compatibility ---


def test_aggregate_false_preserves_existing_behaviour():
    eng = HeuristicEngine()
    obs = [
        _obs(observation_id="oid-1", payload_value="v1"),
        _obs(observation_id="oid-2", payload_value="v2"),
    ]
    matches = [_match(obs_idx=0), _match(obs_idx=1)]
    cands = eng.to_candidates(matches, obs)
    assert len(cands) == 2
    for c in cands:
        assert c.signature_id == ""
        assert c.observation_count == 1
        assert c.payload_families == ()
        assert c.contributing_observation_ids == ()


def test_aggregate_false_with_include_suppressed_preserves_existing():
    eng = HeuristicEngine()
    obs = [
        _obs(observation_id="oid-1"),
        _obs(observation_id="oid-2"),
    ]
    matches = [
        _match(obs_idx=0, suppressed=False),
        _match(obs_idx=1, suppressed=True),
    ]
    cands = eng.to_candidates(matches, obs, include_suppressed=True)
    assert len(cands) == 2
    assert any(c.detail.startswith("[suppressed:") for c in cands)


# --- aggregate path: base shape ---


def test_aggregate_single_match():
    eng = HeuristicEngine()
    obs = [_obs(observation_id="oid-1")]
    matches = [_match(obs_idx=0)]
    cands = eng.to_candidates(matches, obs, aggregate=True)
    assert len(cands) == 1
    c = cands[0]
    assert c.param == "q"
    assert c.url == "http://x/a"
    assert c.method == "GET"
    assert c.observation_count == 1
    assert c.signature_id == "SIG-1"
    assert c.first_observation_id == "oid-1"
    assert c.last_observation_id == "oid-1"
    assert c.payload_families == ("p1",)
    assert c.contributing_observation_ids == ("oid-1",)
    assert c.confidence == 0.5
    assert not c.detail.startswith("[suppressed")
    assert "1 matches across 1 probes" in c.detail


def test_aggregate_multiple_matches_same_param():
    eng = HeuristicEngine()
    obs = [
        _obs(observation_id="oid-1", payload_value="v1"),
        _obs(observation_id="oid-2", payload_value="v2"),
        _obs(observation_id="oid-3", payload_value="v3"),
    ]
    matches = [_match(obs_idx=0), _match(obs_idx=1), _match(obs_idx=2)]
    cands = eng.to_candidates(matches, obs, aggregate=True)
    assert len(cands) == 1
    c = cands[0]
    assert c.observation_count == 3
    assert "3 matches across 3 probes" in c.detail


def test_aggregate_distinct_params_yield_distinct_candidates():
    eng = HeuristicEngine()
    obs = [
        _obs(param="a", observation_id="oid-a"),
        _obs(param="b", observation_id="oid-b"),
    ]
    matches = [_match(obs_idx=0), _match(obs_idx=1)]
    cands = eng.to_candidates(matches, obs, aggregate=True)
    assert len(cands) == 2
    assert {c.param for c in cands} == {"a", "b"}


def test_aggregate_repeated_probe_counts_once():
    eng = HeuristicEngine()
    obs = [
        _obs(observation_id="oid-same", payload_value="v1"),
        _obs(observation_id="oid-same", payload_value="v2"),
    ]
    matches = [_match(obs_idx=0), _match(obs_idx=1)]
    cands = eng.to_candidates(matches, obs, aggregate=True)
    assert len(cands) == 1
    c = cands[0]
    assert c.observation_count == 1
    assert "2 matches across 1 probes" in c.detail


# --- aggregate path: reductions (R1-R5) ---


def test_aggregate_primary_category_from_highest_confidence():
    eng = HeuristicEngine()
    obs = [
        _obs(observation_id="oid-1", payload_value="v1"),
        _obs(observation_id="oid-2", payload_value="v2"),
    ]
    matches = [
        _match(sig_id="SIG-A", category="low:c", obs_idx=0, confidence=0.2),
        _match(sig_id="SIG-B", category="high:c", obs_idx=1, confidence=0.9),
    ]
    cands = eng.to_candidates(matches, obs, aggregate=True)
    assert len(cands) == 1
    assert cands[0].category == "high:c"
    assert cands[0].confidence == 0.9


def test_aggregate_primary_category_tiebreak_by_sig_id():
    eng = HeuristicEngine()
    obs = [
        _obs(observation_id="oid-1", payload_value="v1"),
        _obs(observation_id="oid-2", payload_value="v2"),
    ]
    matches = [
        _match(sig_id="SIG-Z", category="cat:z", obs_idx=0, confidence=0.5),
        _match(sig_id="SIG-A", category="cat:a", obs_idx=1, confidence=0.5),
    ]
    cands = eng.to_candidates(matches, obs, aggregate=True)
    assert len(cands) == 1
    assert cands[0].category == "cat:a"


def test_aggregate_confidence_is_max():
    eng = HeuristicEngine()
    obs = [
        _obs(observation_id="oid-1"),
        _obs(observation_id="oid-2"),
        _obs(observation_id="oid-3"),
    ]
    matches = [
        _match(obs_idx=0, confidence=0.3),
        _match(obs_idx=1, confidence=0.7),
        _match(obs_idx=2, confidence=0.5),
    ]
    cands = eng.to_candidates(matches, obs, aggregate=True)
    assert len(cands) == 1
    assert cands[0].confidence == 0.7


def test_aggregate_signature_id_sorted_comma_joined():
    eng = HeuristicEngine()
    obs = [
        _obs(observation_id="oid-1"),
        _obs(observation_id="oid-2"),
    ]
    matches = [
        _match(sig_id="SIG-B", obs_idx=0),
        _match(sig_id="SIG-A", obs_idx=1),
    ]
    cands = eng.to_candidates(matches, obs, aggregate=True)
    assert len(cands) == 1
    assert cands[0].signature_id == "SIG-A,SIG-B"
    assert cands[0].discovery_reason == "heuristic:SIG-A,SIG-B"


# --- base-field sourcing ---


def test_aggregate_base_fields_from_first_observation():
    eng = HeuristicEngine()
    obs = [
        _obs(observation_id="oid-first", payload_name="pA", payload_value="va"),
        _obs(observation_id="oid-second", payload_name="pB", payload_value="vb"),
    ]
    matches = [_match(obs_idx=0), _match(obs_idx=1)]
    cands = eng.to_candidates(matches, obs, aggregate=True)
    assert len(cands) == 1
    c = cands[0]
    assert c.payload_name == "pA"
    assert c.payload_value == "va"


def test_aggregate_base_fields_use_index_not_lexicographic():
    """Base obs comes from lowest observation_index, not smallest ID."""
    eng = HeuristicEngine()
    obs = [
        _obs(observation_id="zzz-first", payload_value="va"),
        _obs(observation_id="aaa-second", payload_value="vb"),
    ]
    matches = [_match(obs_idx=0), _match(obs_idx=1)]
    cands = eng.to_candidates(matches, obs, aggregate=True)
    assert len(cands) == 1
    assert cands[0].payload_value == "va"


# --- R6: suppressed handling ---


def test_aggregate_suppressed_filtered_when_include_false():
    eng = HeuristicEngine()
    obs = [
        _obs(observation_id="oid-1"),
        _obs(observation_id="oid-2"),
    ]
    matches = [
        _match(obs_idx=0, suppressed=False),
        _match(obs_idx=1, suppressed=True),
    ]
    cands = eng.to_candidates(matches, obs, aggregate=True, include_suppressed=False)
    assert len(cands) == 1
    assert cands[0].observation_count == 1
    assert not cands[0].detail.startswith("[suppressed")
    assert not cands[0].detail.startswith("[includes")


def test_aggregate_all_suppressed_uses_suppressed_prefix():
    eng = HeuristicEngine()
    obs = [
        _obs(observation_id="oid-1"),
        _obs(observation_id="oid-2"),
    ]
    matches = [
        _match(obs_idx=0, suppressed=True),
        _match(obs_idx=1, suppressed=True),
    ]
    cands = eng.to_candidates(matches, obs, aggregate=True, include_suppressed=True)
    assert len(cands) == 1
    assert cands[0].detail.startswith("[suppressed: baseline_match]")


def test_aggregate_mixed_suppression_advisory():
    eng = HeuristicEngine()
    obs = [
        _obs(observation_id="oid-1"),
        _obs(observation_id="oid-2"),
    ]
    matches = [
        _match(obs_idx=0, suppressed=False),
        _match(obs_idx=1, suppressed=True),
    ]
    cands = eng.to_candidates(matches, obs, aggregate=True, include_suppressed=True)
    assert len(cands) == 1
    assert cands[0].detail.startswith("[includes 1 suppressed]")
    assert not cands[0].detail.startswith("[suppressed:")


# --- no mutation, determinism ---


def test_aggregate_does_not_mutate_inputs():
    eng = HeuristicEngine()
    obs = [_obs(observation_id="oid-1"), _obs(observation_id="oid-2")]
    matches = [_match(obs_idx=0), _match(obs_idx=1)]
    obs_before = list(obs)
    matches_before = list(matches)
    eng.to_candidates(matches, obs, aggregate=True)
    assert len(obs) == len(obs_before)
    assert len(matches) == len(matches_before)
    for a, b in zip(obs, obs_before, strict=True):
        assert a is b
    for a, b in zip(matches, matches_before, strict=True):
        assert a is b


def test_aggregate_deterministic_regardless_of_match_order():
    eng = HeuristicEngine()
    obs = [
        _obs(observation_id="oid-1", payload_value="v1"),
        _obs(observation_id="oid-2", payload_value="v2"),
    ]
    m1 = _match(sig_id="SIG-A", category="cat:a", obs_idx=0, confidence=0.6)
    m2 = _match(sig_id="SIG-B", category="cat:b", obs_idx=1, confidence=0.6)
    a = eng.to_candidates([m1, m2], obs, aggregate=True)
    b = eng.to_candidates([m2, m1], obs, aggregate=True)
    assert len(a) == len(b) == 1
    assert a[0].signature_id == b[0].signature_id == "SIG-A,SIG-B"
    assert a[0].category == b[0].category == "cat:a"
