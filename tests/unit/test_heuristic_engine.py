"""Tests for src/janissary/heuristic/engine.py (M38)."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from janissary.heuristic.engine import HeuristicEngine, HeuristicMatch
from janissary.heuristic.signatures import HEURISTIC_SIGNATURES, HeuristicSignature
from janissary.heuristic.types import Observation


def test_observation_valid_construction():
    obs = Observation(url="http://x/", body="hello", param="q")
    assert obs.url == "http://x/"
    assert obs.body == "hello"
    assert obs.param == "q"


def test_observation_is_frozen():
    obs = Observation(url="http://x/", body="hello")
    with pytest.raises(FrozenInstanceError):
        obs.url = "http://y/"


def test_observation_defaults():
    obs = Observation(url="http://x/", body="hello")
    assert obs.headers == {}
    assert obs.method == "GET"
    assert obs.response_status is None
    assert obs.payload_name == ""
    assert obs.payload_value == ""
    assert obs.param == ""


def test_engine_uses_default_signatures():
    e = HeuristicEngine()
    assert e._signatures is HEURISTIC_SIGNATURES


def test_engine_custom_signatures():
    sig = HeuristicSignature(
        id="HEUR-TEST", category="test", target_layer="body", patterns=(r"foo",)
    )
    e = HeuristicEngine(signatures=(sig,))
    assert e._signatures == (sig,)


def test_match_empty_observations():
    assert HeuristicEngine().match([]) == []


def test_match_no_match():
    obs = Observation(url="http://x/", body="hello world")
    assert HeuristicEngine().match([obs]) == []


def test_match_finds_sqli_error():
    obs = Observation(
        url="http://x/", body="You have an error in your SQL syntax near MySQL"
    )
    matches = HeuristicEngine().match([obs])
    assert any(m.signature_id == "HEUR-001" for m in matches)


def test_match_finds_passwd_leak():
    obs = Observation(url="http://x/", body="root:x:0:0:root:/root:/bin/bash")
    matches = HeuristicEngine().match([obs])
    assert any(m.signature_id == "HEUR-002" for m in matches)


def test_match_finds_traceback():
    obs = Observation(
        url="http://x/", body="Traceback (most recent call last): File test.py"
    )
    matches = HeuristicEngine().match([obs])
    assert any(m.signature_id == "HEUR-003" for m in matches)


def test_match_finds_header_pattern():
    obs = Observation(
        url="http://x/",
        body="",
        headers={"X-Debug": "Traceback (most recent call last):"},
    )
    matches = HeuristicEngine().match([obs])
    assert any(m.signature_id == "HEUR-003" for m in matches)


def test_match_preserves_observation_order():
    obs1 = Observation(url="http://x/1", body="root:x:0:0:root")
    obs2 = Observation(url="http://x/2", body="SQL syntax error near MySQL")
    matches = HeuristicEngine().match([obs1, obs2])
    idxs = [m.observation_index for m in matches]
    assert idxs == sorted(idxs)


def test_match_one_pattern_per_signature_per_observation():
    obs = Observation(
        url="http://x/", body="SQL syntax error near MySQL also ORA-12345"
    )
    matches = HeuristicEngine().match([obs])
    heur_001 = [m for m in matches if m.signature_id == "HEUR-001"]
    assert len(heur_001) == 1


def test_to_candidates_empty():
    assert HeuristicEngine().to_candidates([], []) == []


def test_to_candidates_discovery_reason():
    obs = Observation(url="http://x/", body="SQL syntax error near MySQL", param="q")
    e = HeuristicEngine()
    candidates = e.to_candidates(e.match([obs]), [obs])
    assert candidates[0].discovery_reason == "heuristic:HEUR-001"


def test_to_candidates_severity_low():
    obs = Observation(url="http://x/", body="SQL syntax error near MySQL", param="q")
    e = HeuristicEngine()
    candidates = e.to_candidates(e.match([obs]), [obs])
    assert all(c.severity == "low" for c in candidates)


def test_to_candidates_finding_type_transformation():
    obs = Observation(url="http://x/", body="SQL syntax error near MySQL", param="q")
    e = HeuristicEngine()
    candidates = e.to_candidates(e.match([obs]), [obs])
    assert any(c.finding_type == "heuristic_sqli_error_leak" for c in candidates)


def test_to_candidates_copies_observation():
    obs = Observation(
        url="http://x/path",
        body="SQL syntax error near MySQL",
        method="POST",
        response_status=500,
        payload_name="sql_q",
        payload_value="\x27",
        param="q",
    )
    e = HeuristicEngine()
    candidates = e.to_candidates(e.match([obs]), [obs])
    assert candidates[0].url == "http://x/path"
    assert candidates[0].method == "POST"
    assert candidates[0].response_status == 500
    assert candidates[0].param == "q"
    assert candidates[0].payload_name == "sql_q"


def test_heuristic_match_is_frozen():
    m = HeuristicMatch(
        signature_id="X",
        category="c",
        target_layer="body",
        matched_pattern="p",
        evidence_excerpt="e",
        confidence=0.5,
        observation_index=0,
    )
    with pytest.raises(FrozenInstanceError):
        m.signature_id = "Y"


def test_select_target_headers_uses_real_newline():
    obs = Observation(
        url="http://x/",
        body="",
        headers={"Set-Cookie": "a=b\nc=d"},
    )
    tgt = HeuristicEngine._select_target("headers", obs)
    assert "\n" in tgt
    assert "\\n" not in tgt


def test_select_target_both_uses_real_newline():
    obs = Observation(
        url="http://x/",
        body="body-text",
        headers={"X": "y"},
    )
    tgt = HeuristicEngine._select_target("both", obs)
    assert "body-text" in tgt
    assert "\n" in tgt
    assert "\\n" not in tgt


# --- M82a: heuristic multi-signal aggregation ---

from janissary.heuristic.engine import MatchGroup  # noqa: E402


def _agg_obs(
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
    from janissary.heuristic.types import Observation

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


def _agg_match(
    *,
    sig_id="SIG-1",
    category="cat:a",
    obs_idx=0,
    confidence=0.5,
    matched_pattern=r"MARK",
):
    return HeuristicMatch(
        signature_id=sig_id,
        category=category,
        target_layer="body",
        matched_pattern=matched_pattern,
        evidence_excerpt="MARK",
        confidence=confidence,
        observation_index=obs_idx,
    )


def test_aggregate_empty_returns_empty_list():
    eng = HeuristicEngine()
    assert eng.aggregate([], []) == []


def test_aggregate_single_match():
    eng = HeuristicEngine()
    obs = [_agg_obs(observation_id="oid-only")]
    matches = [_agg_match(obs_idx=0)]
    groups = eng.aggregate(matches, obs)
    assert len(groups) == 1
    g = groups[0]
    assert isinstance(g, MatchGroup)
    assert g.url == "http://x/a"
    assert g.method == "GET"
    assert g.param == "q"
    assert len(g.matches) == 1
    assert g.signature_ids == frozenset({"SIG-1"})
    assert g.categories == frozenset({"cat:a"})
    assert g.confidences == frozenset({0.5})
    assert g.payload_families == frozenset({"p1"})
    assert g.contributing_observation_ids == ("oid-only",)
    assert g.first_observation_index == 0
    assert g.last_observation_index == 0
    assert g.first_observation_id == "oid-only"
    assert g.last_observation_id == "oid-only"


def test_aggregate_groups_same_url_method_param():
    eng = HeuristicEngine()
    obs = [
        _agg_obs(payload_value="v1", observation_id="oid-1"),
        _agg_obs(payload_value="v2", observation_id="oid-2"),
    ]
    matches = [_agg_match(obs_idx=0), _agg_match(obs_idx=1)]
    groups = eng.aggregate(matches, obs)
    assert len(groups) == 1
    g = groups[0]
    assert len(g.matches) == 2
    assert g.contributing_observation_ids == ("oid-1", "oid-2")


def test_aggregate_distinct_by_url():
    eng = HeuristicEngine()
    obs = [
        _agg_obs(url="http://x/a", observation_id="oid-a"),
        _agg_obs(url="http://x/b", observation_id="oid-b"),
    ]
    matches = [_agg_match(obs_idx=0), _agg_match(obs_idx=1)]
    groups = eng.aggregate(matches, obs)
    assert len(groups) == 2
    assert {g.url for g in groups} == {"http://x/a", "http://x/b"}


def test_aggregate_distinct_by_method():
    eng = HeuristicEngine()
    obs = [
        _agg_obs(method="GET", observation_id="oid-g"),
        _agg_obs(method="POST", observation_id="oid-p"),
    ]
    matches = [_agg_match(obs_idx=0), _agg_match(obs_idx=1)]
    groups = eng.aggregate(matches, obs)
    assert len(groups) == 2
    assert {g.method for g in groups} == {"GET", "POST"}


def test_aggregate_dedupes_repeated_observation_id():
    eng = HeuristicEngine()
    obs = [
        _agg_obs(observation_id="oid-same", payload_value="v1"),
        _agg_obs(observation_id="oid-same", payload_value="v2"),
    ]
    matches = [_agg_match(obs_idx=0), _agg_match(obs_idx=1)]
    groups = eng.aggregate(matches, obs)
    assert len(groups) == 1
    assert groups[0].contributing_observation_ids == ("oid-same",)


def test_aggregate_multiple_signatures():
    eng = HeuristicEngine()
    obs = [
        _agg_obs(observation_id="oid-1", payload_value="v1"),
        _agg_obs(observation_id="oid-2", payload_value="v2"),
    ]
    matches = [
        _agg_match(sig_id="SIG-1", obs_idx=0),
        _agg_match(sig_id="SIG-2", obs_idx=1),
    ]
    groups = eng.aggregate(matches, obs)
    assert len(groups) == 1
    assert groups[0].signature_ids == frozenset({"SIG-1", "SIG-2"})


def test_aggregate_multiple_categories():
    eng = HeuristicEngine()
    obs = [
        _agg_obs(observation_id="oid-1", payload_value="v1"),
        _agg_obs(observation_id="oid-2", payload_value="v2"),
    ]
    matches = [
        _agg_match(category="sqli:error", obs_idx=0),
        _agg_match(category="debug:disclosure", obs_idx=1),
    ]
    groups = eng.aggregate(matches, obs)
    assert len(groups) == 1
    assert groups[0].categories == frozenset({"sqli:error", "debug:disclosure"})


def test_aggregate_multiple_confidences():
    eng = HeuristicEngine()
    obs = [
        _agg_obs(observation_id="oid-1", payload_value="v1"),
        _agg_obs(observation_id="oid-2", payload_value="v2"),
    ]
    matches = [
        _agg_match(confidence=0.4, obs_idx=0),
        _agg_match(confidence=0.6, obs_idx=1),
    ]
    groups = eng.aggregate(matches, obs)
    assert len(groups) == 1
    assert groups[0].confidences == frozenset({0.4, 0.6})


def test_aggregate_payload_families_skips_empty():
    eng = HeuristicEngine()
    obs = [
        _agg_obs(observation_id="oid-1", payload_name="quote", payload_value="v1"),
        _agg_obs(observation_id="oid-2", payload_name="union", payload_value="v2"),
        _agg_obs(observation_id="oid-3", payload_name="", payload_value="v3"),
    ]
    matches = [
        _agg_match(obs_idx=0),
        _agg_match(obs_idx=1),
        _agg_match(obs_idx=2),
    ]
    groups = eng.aggregate(matches, obs)
    assert len(groups) == 1
    assert groups[0].payload_families == frozenset({"quote", "union"})


def test_aggregate_first_last_ids_use_index_not_lexicographic():
    """R1 detail: first/last IDs are at min/max original indices, not
    lexicographically smallest/largest IDs."""
    eng = HeuristicEngine()
    obs = [
        _agg_obs(observation_id="zzz-first", payload_value="v1"),
        _agg_obs(observation_id="aaa-last", payload_value="v2"),
    ]
    matches = [_agg_match(obs_idx=0), _agg_match(obs_idx=1)]
    groups = eng.aggregate(matches, obs)
    assert len(groups) == 1
    g = groups[0]
    assert g.first_observation_index == 0
    assert g.last_observation_index == 1
    assert g.first_observation_id == "zzz-first"
    assert g.last_observation_id == "aaa-last"
    assert g.contributing_observation_ids == ("aaa-last", "zzz-first")


def test_aggregate_sorted_by_first_observation_index():
    eng = HeuristicEngine()
    obs = [
        _agg_obs(url="http://x/late", observation_id="oid-late", payload_value="v0"),
        _agg_obs(url="http://x/early", observation_id="oid-early", payload_value="v1"),
    ]
    matches = [_agg_match(obs_idx=0), _agg_match(obs_idx=1)]
    groups = eng.aggregate(matches, obs)
    assert len(groups) == 2
    assert groups[0].url == "http://x/late"
    assert groups[1].url == "http://x/early"
