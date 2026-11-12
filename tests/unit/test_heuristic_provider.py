"""Tests for observation providers (M80)."""

import re
from pathlib import Path

import pytest

from janissary.engine.scanner import Scanner
from janissary.heuristic.engine import HeuristicEngine
from janissary.heuristic.provider import (
    ObservationLoadError,
    ScannerProvider,
    StaticFixtureProvider,
    _compute_observation_id,
)
from janissary.heuristic.types import Observation

FIXTURES = Path(__file__).parent.parent / "fixtures" / "heuristic"


def _scanner_with_obs(obs_list):
    s = Scanner(target="http://x/", params=["q"], method="GET", detect_waf=False)
    s._observations = list(obs_list)
    return s


def _simple_obs(
    url="http://x/a", method="GET", param="q", payload_name="p", payload_value="v"
):
    return Observation(
        url=url,
        body="b",
        method=method,
        param=param,
        payload_name=payload_name,
        payload_value=payload_value,
    )


def test_scanner_provider_returns_scanner_observations():
    src = _simple_obs()
    sc = _scanner_with_obs([src])
    got = ScannerProvider(sc).observations()
    assert len(got) == 1
    assert got[0].url == src.url
    assert got[0].body == src.body


def test_scanner_provider_source_id_format():
    sc = _scanner_with_obs([])
    p = ScannerProvider(sc)
    assert re.fullmatch(r"scanner:[0-9a-f]+", p.source_id)


def test_scanner_provider_observation_id_is_full_sha256():
    sc = _scanner_with_obs([_simple_obs()])
    got = ScannerProvider(sc).observations()
    assert re.fullmatch(r"[0-9a-f]{64}", got[0].observation_id)


def test_static_fixture_provider_loads_valid_single():
    p = StaticFixtureProvider(FIXTURES / "valid_single.jsonl")
    obs = p.observations()
    assert len(obs) == 1
    assert p.source_id == "fixture"
    assert obs[0].source_id == "fixture"
    assert re.fullmatch(r"[0-9a-f]{64}", obs[0].observation_id)


def test_static_fixture_provider_loads_multiple_same_source():
    obs = StaticFixtureProvider(
        FIXTURES / "valid_multi_same_source.jsonl"
    ).observations()
    assert len(obs) == 3
    assert all(o.source_id == "fixture" for o in obs)
    assert len({o.observation_id for o in obs}) == 3


def test_static_fixture_provider_loads_multiple_sources():
    p1 = StaticFixtureProvider(
        FIXTURES / "valid_multi_sources.jsonl", source_id="source-a"
    )
    p2 = StaticFixtureProvider(
        FIXTURES / "valid_multi_sources.jsonl", source_id="source-b"
    )
    o1 = p1.observations()
    o2 = p2.observations()
    assert {o.observation_id for o in o1} == {o.observation_id for o in o2}
    assert all(o.source_id == "source-a" for o in o1)
    assert all(o.source_id == "source-b" for o in o2)


def test_observation_id_deterministic_across_loads():
    a = StaticFixtureProvider(FIXTURES / "valid_multi_same_source.jsonl").observations()
    b = StaticFixtureProvider(FIXTURES / "valid_multi_same_source.jsonl").observations()
    assert [o.observation_id for o in a] == [o.observation_id for o in b]


def test_observation_id_content_addressed_not_instance():
    o1 = Observation(
        url="http://x/a",
        body="A",
        method="GET",
        param="q",
        payload_name="p",
        payload_value="v",
    )
    o2 = Observation(
        url="http://x/a",
        body="B",
        method="GET",
        param="q",
        payload_name="p",
        payload_value="v",
    )
    id1 = _compute_observation_id(
        o1.url, o1.method, o1.param, o1.payload_name, o1.payload_value
    )
    id2 = _compute_observation_id(
        o2.url, o2.method, o2.param, o2.payload_name, o2.payload_value
    )
    assert id1 == id2


def test_observation_id_is_full_sha256():
    o = _simple_obs()
    oid = _compute_observation_id(
        o.url, o.method, o.param, o.payload_name, o.payload_value
    )
    assert len(oid) == 64
    assert re.fullmatch(r"[0-9a-f]{64}", oid)


@pytest.mark.parametrize(
    "sid",
    ["fixture", "scanner:abc123", "provider_1", "source-a", "a"],
)
def test_valid_source_id_accepted(tmp_path, sid):
    f = tmp_path / "valid.jsonl"
    f.write_text("{}", encoding="utf-8")
    provider = StaticFixtureProvider(f, source_id=sid)
    assert provider.source_id == sid


@pytest.mark.parametrize(
    "sid",
    [
        "",
        "Scanner",
        " scanner",
        "scanner ",
        "-scanner",
        "scanner-",
        "scanner_",
        "scanner:",
        "scanner:inline ",
    ],
)
def test_invalid_source_id_rejected(tmp_path, sid):
    f = tmp_path / "e.jsonl"
    f.write_text('{"url": "u", "body": "b"}\n', encoding="utf-8")
    with pytest.raises(ObservationLoadError) as exc:
        StaticFixtureProvider(f, source_id=sid)
    assert exc.value.category == "invalid_provider_id"


def test_malformed_json_raises_with_line_number():
    with pytest.raises(ObservationLoadError) as exc:
        StaticFixtureProvider(FIXTURES / "malformed_json.jsonl").observations()
    assert exc.value.category == "malformed_json"
    assert exc.value.line_number == 2


def test_missing_required_field_raises():
    with pytest.raises(ObservationLoadError) as exc:
        StaticFixtureProvider(FIXTURES / "missing_required_field.jsonl").observations()
    assert exc.value.category == "missing_required"


def test_unknown_field_rejected(tmp_path):
    f = tmp_path / "u.jsonl"
    f.write_text('{"url": "u", "body": "b", "foo": "bar"}\n', encoding="utf-8")
    with pytest.raises(ObservationLoadError) as exc:
        StaticFixtureProvider(f).observations()
    assert exc.value.category == "unknown_field"


def test_reserved_verification_field_rejected():
    with pytest.raises(ObservationLoadError) as exc:
        StaticFixtureProvider(FIXTURES / "reserved_verification.jsonl").observations()
    assert exc.value.category == "reserved_verification"
    assert "verification_status" in str(exc.value)


def test_provider_supplied_field_rejected(tmp_path):
    f = tmp_path / "p.jsonl"
    f.write_text('{"url": "u", "body": "b", "source_id": "x"}\n', encoding="utf-8")
    with pytest.raises(ObservationLoadError) as exc:
        StaticFixtureProvider(f).observations()
    assert exc.value.category == "provider_supplied"


def test_confidence_field_rejected_as_non_observation(tmp_path):
    f = tmp_path / "c.jsonl"
    f.write_text('{"url": "u", "body": "b", "confidence": 0.9}\n', encoding="utf-8")
    with pytest.raises(ObservationLoadError) as exc:
        StaticFixtureProvider(f).observations()
    assert exc.value.category == "non_observation_field"


@pytest.mark.parametrize(
    "bad",
    [
        '{"url": 1, "body": "b"}',
        '{"url": "u", "body": ["l"]}',
        '{"url": "u", "body": "b", "method": 123}',
        '{"url": "u", "body": "b", "response_status": "200"}',
        '{"url": "u", "body": "b", "headers": {"X": 1}}',
    ],
)
def test_invalid_field_types_rejected(tmp_path, bad):
    f = tmp_path / "t.jsonl"
    f.write_text(bad + "\n", encoding="utf-8")
    with pytest.raises(ObservationLoadError) as exc:
        StaticFixtureProvider(f).observations()
    assert exc.value.category == "invalid_field_type"


def test_oversized_evidence_rejected(tmp_path):
    f = tmp_path / "big.jsonl"
    body = "A" * 1_000_001
    import json as _j

    f.write_text(_j.dumps({"url": "u", "body": body}) + "\n", encoding="utf-8")
    with pytest.raises(ObservationLoadError) as exc:
        StaticFixtureProvider(f).observations()
    assert exc.value.category == "oversized_evidence"


def test_provider_output_reaches_engine_as_candidates_not_findings():
    provider = StaticFixtureProvider(FIXTURES / "valid_single.jsonl")
    obs = provider.observations()
    engine = HeuristicEngine()
    matches = engine.match(obs)
    candidates = engine.to_candidates(matches, obs)
    for c in candidates:
        assert not hasattr(c, "verification_status") or c.verification_status is None
    from janissary.engine.scanner import ScanFinding

    for c in candidates:
        assert not isinstance(c, ScanFinding)
