"""Tests for GraphQLNormalizer (Phase 0.3 + FN-15)."""

import json
from unittest.mock import MagicMock

from janissary.protocols import BaselineNormalizer, NormalizedResponse
from janissary.protocols.graphql import GraphQLNormalizer


def _resp(body, status=200, headers=None):
    r = MagicMock()
    r.text = body if isinstance(body, str) else json.dumps(body)
    r.status_code = status
    r.headers = headers or {"content-type": "application/json"}
    return r


def test_graphql_normalizer_satisfies_baseline_protocol():
    assert isinstance(GraphQLNormalizer(), BaselineNormalizer)
    assert GraphQLNormalizer.protocol_name == "graphql"


def test_sorts_keys_recursively():
    n = GraphQLNormalizer()
    r = _resp({"data": {"user": {"z": 1, "a": 2, "m": {"y": 3, "b": 4}}}})
    out = n.normalize(r)
    # Parsed body must have sorted keys top-down
    parsed = json.loads(out.body)
    assert list(parsed.keys()) == ["data"]
    assert list(parsed["data"]["user"].keys()) == ["a", "m", "z"]
    assert list(parsed["data"]["user"]["m"].keys()) == ["b", "y"]


def test_strips_extensions():
    n = GraphQLNormalizer()
    r = _resp({"data": {"x": 1}, "extensions": {"tracing": {"duration": 42}}})
    out = n.normalize(r)
    parsed = json.loads(out.body)
    assert "extensions" not in parsed
    assert "body:extensions_stripped" in out.stripped


def test_strips_extensions_in_errors():
    n = GraphQLNormalizer()
    r = _resp({"errors": [{"message": "boom", "extensions": {"code": "X"}}]})
    out = n.normalize(r)
    parsed = json.loads(out.body)
    assert "extensions" not in parsed["errors"][0]
    assert parsed["errors"][0]["message"] == "boom"


def test_strips_timing_keys():
    n = GraphQLNormalizer()
    r = _resp({"data": {"duration": 1.5, "value": 42}})
    out = n.normalize(r)
    parsed = json.loads(out.body)
    assert "duration" not in parsed["data"]
    assert parsed["data"]["value"] == 42
    assert "body:timing_keys_stripped" in out.stripped


def test_preserves_data_and_errors():
    n = GraphQLNormalizer()
    r = _resp({"data": {"user": {"name": "alice"}}, "errors": [{"message": "warn"}]})
    out = n.normalize(r)
    parsed = json.loads(out.body)
    assert parsed["data"]["user"]["name"] == "alice"
    assert parsed["errors"][0]["message"] == "warn"


def test_non_json_falls_back_to_http_normalizer():
    n = GraphQLNormalizer()
    r = _resp("  not json  \n\n  plain  ", headers={"content-type": "text/html"})
    out = n.normalize(r)
    assert "body:non_json_fallback" in out.stripped
    # HTTP normalizer collapses whitespace: body must be collapsed
    assert "  " not in out.body


def test_deterministic_across_input_key_orders():
    n = GraphQLNormalizer()
    a = n.normalize(_resp({"b": 2, "a": 1}))
    b = n.normalize(_resp({"a": 1, "b": 2}))
    assert a.body == b.body


def test_length_matches_body():
    n = GraphQLNormalizer()
    out = n.normalize(_resp({"data": {"x": 1}}))
    assert out.length == len(out.body)


def test_status_and_headers_preserved():
    n = GraphQLNormalizer()
    out = n.normalize(_resp({"data": {}}, status=200, headers={"x-id": "abc"}))
    assert out.status == 200
    assert out.headers["x-id"] == "abc"


def test_response_shape_is_normalized_response():
    n = GraphQLNormalizer()
    out = n.normalize(_resp({"data": {}}))
    assert isinstance(out, NormalizedResponse)
    assert isinstance(out.stripped, tuple)
