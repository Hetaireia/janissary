"""Unit tests for the GraphQL harness."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from janissary.integrations import graphql as g


class FakeResp:
    def __init__(self, status=200, body=None, text=None, headers=None):
        self.status_code = status
        self.headers = headers or {}
        self._body = body
        self.text = (
            text if text is not None else (json.dumps(body) if body is not None else "")
        )

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


def _session(responses):
    s = MagicMock()
    s.post.side_effect = list(responses)
    return s


def _client(responses, endpoint="http://t/graphql"):
    return g.GraphQLClient(endpoint, session=_session(responses))


# ---------------------------------------------------------------------------
# Query builders
# ---------------------------------------------------------------------------


def test_build_nested_query_depth_1():
    assert g.build_nested_query("__typename", 1) == "{ __typename }"


def test_build_nested_query_depth_3():
    q = g.build_nested_query("user", 3)
    assert q == "{ user { user { user } } }"


def test_build_alias_query_count():
    q = g.build_alias_query("__typename", 3)
    assert q == "{ a0: __typename a1: __typename a2: __typename }"


def test_build_argument_query_string():
    q = g.build_argument_query("user", "id", "abc")
    assert q == '{ user(id: "abc") }'


def test_build_argument_query_dict():
    q = g.build_argument_query("user", "where", {"a": 1})
    assert q == "{ user(where: {a: 1}) }"


def test_gql_literal_escapes_quotes():
    lit = g._gql_literal('he said "hi"')
    assert lit == '"he said \\"hi\\""'


def test_gql_literal_null_byte():
    lit = g._gql_literal("\x00")
    assert lit == '"\\u0000"'


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


def test_parse_success():
    body = {"data": {"__typename": "Query"}}
    client = _client([FakeResp(body=body)])
    resp = client.query(g.TYPENAME_QUERY)
    assert resp.ok is True
    assert resp.data == {"__typename": "Query"}
    assert resp.errors == []


def test_parse_graphql_error():
    body = {"errors": [{"message": "bad field"}]}
    client = _client([FakeResp(body=body)])
    resp = client.query("{ bad }")
    assert resp.error_messages() == ["bad field"]


def test_parse_non_json_body():
    client = _client([FakeResp(body=None, text="<html>oops</html>")])
    resp = client.query("{ x }")
    assert resp.body == "<html>oops</html>"


def test_transport_error():
    import requests

    session = MagicMock()
    session.post.side_effect = requests.RequestException("boom")
    client = g.GraphQLClient("http://t/graphql", session=session)
    resp = client.query("{ x }")
    assert resp.status is None
    assert "transport error" in resp.note


def test_batch_response():
    body = [{"data": {"__typename": "Query"}}, {"data": {"__typename": "Query"}}]
    client = _client([FakeResp(body=body)])
    resp = client.batch([g.TYPENAME_QUERY, g.TYPENAME_QUERY])
    assert isinstance(resp.body, list)


# ---------------------------------------------------------------------------
# Endpoint resolution
# ---------------------------------------------------------------------------


def test_resolve_endpoint_candidates():
    urls = g.resolve_endpoint("http://t")
    assert "http://t/graphql" in urls
    assert "http://t/api/graphql" in urls


def test_resolve_endpoint_explicit_path():
    urls = g.resolve_endpoint("http://t", explicit_path="/custom/gql")
    assert urls[0] == "http://t/custom/gql"


def test_resolve_endpoint_recognises_graphql_url():
    urls = g.resolve_endpoint("http://t/graphql")
    assert urls[0] == "http://t/graphql"


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def test_detect_introspection_enabled():
    typename_body = {"data": {"__typename": "Query"}}
    schema = {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "subscriptionType": None,
            "types": [{"name": "Query"}, {"name": "Mutation"}],
        }
    }
    intro_body = {"data": schema}
    batch_body = [{"data": {"__typename": "Query"}}, {"data": {"__typename": "Query"}}]
    suggestion_body = {
        "errors": [{"message": 'Cannot query field "x". Did you mean "user"?'}]
    }

    client = _client(
        [
            FakeResp(body=typename_body),
            FakeResp(body=intro_body),
            FakeResp(body=batch_body),
            FakeResp(body=suggestion_body),
        ]
    )
    profile = g.detect("http://t/graphql", client=client)
    assert profile.reachable is True
    assert profile.introspection_enabled is True
    assert profile.query_type == "Query"
    assert profile.mutation_type == "Mutation"
    assert profile.type_count == 2
    assert profile.batched_queries is True
    assert profile.suggestions_supported is True


def test_detect_introspection_disabled():
    typename_body = {"data": {"__typename": "Query"}}
    intro_body = {"errors": [{"message": "Introspection is disabled"}]}
    batch_body = {"errors": [{"message": "batch not supported"}]}
    suggestion_body = {"errors": [{"message": "no suggestion"}]}

    client = _client(
        [
            FakeResp(body=typename_body),
            FakeResp(body=intro_body),
            FakeResp(body=batch_body),
            FakeResp(body=suggestion_body),
        ]
    )
    profile = g.detect("http://t/graphql", client=client)
    assert profile.reachable is True
    assert profile.introspection_enabled is False
    assert profile.schema is None


def test_detect_http_error():
    client = _client([FakeResp(status=404, body={})])
    profile = g.detect("http://t/graphql", client=client)
    assert profile.reachable is False
    assert any("404" in n for n in profile.notes)


def test_profile_to_dict():
    p = g.GraphQLProfile(endpoint="http://t/graphql", reachable=True)
    d = p.to_dict()
    assert d["endpoint"] == "http://t/graphql"
    assert d["reachable"] is True


# ---------------------------------------------------------------------------
# Field enumeration
# ---------------------------------------------------------------------------


def test_enumerate_fields_from_suggestions():
    suggestion_body = {"errors": [{"message": 'Did you mean "user"?'}]}

    # Two rounds: first round uses 26 seed chars, second uses any found.
    responses = [FakeResp(body=suggestion_body)] * 30
    client = _client(responses)
    names = g.enumerate_fields(client, max_rounds=1)
    assert "user" in names


def test_enumerate_fields_no_suggestions():
    body = {"errors": [{"message": "no suggestion"}]}
    responses = [FakeResp(body=body)] * 30
    client = _client(responses)
    names = g.enumerate_fields(client, max_rounds=1)
    assert names == []


# ---------------------------------------------------------------------------
# Depth and alias probes
# ---------------------------------------------------------------------------


def _stateful_depth_session(cap):
    """Return a session that errors once the nesting depth exceeds ``cap``."""
    session = MagicMock()

    def post(url, data, **kwargs):
        payload = json.loads(data.decode("utf-8") if isinstance(data, bytes) else data)
        depth = payload["query"].count("{")
        if depth > cap:
            return FakeResp(
                body={"errors": [{"message": "Query depth exceeds maximum"}]}
            )
        return FakeResp(body={"data": {"__typename": "Query"}})

    session.post.side_effect = post
    return session


def test_depth_probe_finds_cap():
    session = _stateful_depth_session(cap=4)
    client = g.GraphQLClient("http://t/graphql", session=session)
    depth, refusal = g.depth_probe(client, start=1, ceiling=32)
    assert depth == 4
    assert "depth" in refusal.lower()


def _stateful_alias_session(cap):
    """Return a session that errors once the alias count exceeds ``cap``."""
    import re as _re

    session = MagicMock()

    def post(url, data, **kwargs):
        payload = json.loads(data.decode("utf-8") if isinstance(data, bytes) else data)
        n = len(_re.findall(r"a\d+:", payload["query"]))
        if n > cap:
            return FakeResp(body={"errors": [{"message": "Too many aliases"}]})
        return FakeResp(body={"data": {"__typename": "Query"}})

    session.post.side_effect = post
    return session


def test_alias_probe_finds_cap():
    session = _stateful_alias_session(cap=100)
    client = g.GraphQLClient("http://t/graphql", session=session)
    count, refusal = g.alias_probe(client, start=10, ceiling=1000)
    assert count == 100
    assert "alias" in refusal.lower()


# ---------------------------------------------------------------------------
# Argument fuzzing
# ---------------------------------------------------------------------------


def test_fuzz_arguments_runs_all_payloads():
    body = {"data": {"user": None}}
    responses = [FakeResp(body=body)] * len(g.ARG_PAYLOADS)
    client = _client(responses)
    results = g.fuzz_arguments(client, "user", "id")
    assert len(results) == len(g.ARG_PAYLOADS)
    names = [r.payload_name for r in results]
    assert "sqli_quote" in names
    assert "ssrf_url" in names


def test_fuzz_arguments_reports_errors():
    body = {"errors": [{"message": "argument id invalid"}]}
    client = _client([FakeResp(body=body)])
    results = g.fuzz_arguments(
        client,
        "user",
        "id",
        payloads=[("one", "x")],
    )
    assert len(results) == 1
    assert results[0].errors == ["argument id invalid"]
