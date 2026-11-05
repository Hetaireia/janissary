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
    sig = HeuristicSignature(id="HEUR-TEST", category="test", target_layer="body", patterns=(r"foo",))
    e = HeuristicEngine(signatures=(sig,))
    assert e._signatures == (sig,)


def test_match_empty_observations():
    assert HeuristicEngine().match([]) == []


def test_match_no_match():
    obs = Observation(url="http://x/", body="hello world")
    assert HeuristicEngine().match([obs]) == []


def test_match_finds_sqli_error():
    obs = Observation(url="http://x/", body="You have an error in your SQL syntax near MySQL")
    matches = HeuristicEngine().match([obs])
    assert any(m.signature_id == "HEUR-001" for m in matches)


def test_match_finds_passwd_leak():
    obs = Observation(url="http://x/", body="root:x:0:0:root:/root:/bin/bash")
    matches = HeuristicEngine().match([obs])
    assert any(m.signature_id == "HEUR-002" for m in matches)


def test_match_finds_traceback():
    obs = Observation(url="http://x/", body="Traceback (most recent call last): File test.py")
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
    obs = Observation(url="http://x/", body="SQL syntax error near MySQL also ORA-12345")
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
