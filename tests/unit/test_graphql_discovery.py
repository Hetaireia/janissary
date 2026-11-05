"""Tests for GraphQLDiscoveryModule (Phase 2.1 + FN-15 part 2)."""

from unittest.mock import MagicMock, patch

from janissary.integrations.graphql import FuzzResult, GraphQLProfile
from janissary.integrations.graphql_discovery import GraphQLDiscoveryModule
from janissary.verification.types import CandidateFinding


def _profile(**kw):
    base = {"endpoint": "http://x/graphql", "reachable": True}
    base.update(kw)
    return GraphQLProfile(**base)


def _module(profile=None, **profile_kw):
    p = profile if profile is not None else _profile(**profile_kw)
    return GraphQLDiscoveryModule(MagicMock(), p)


def test_discover_returns_list_of_candidates():
    m = _module()
    out = m.discover(include_probes=False, include_fuzz=False)
    assert isinstance(out, list)
    for c in out:
        assert isinstance(c, CandidateFinding)


def test_introspection_enabled_emits_candidate():
    m = _module(introspection_enabled=True, type_count=42)
    out = m.discover(include_probes=False)
    intros = [c for c in out if c.finding_type == "graphql_introspection_enabled"]
    assert len(intros) == 1
    assert "42 types" in intros[0].detail
    assert intros[0].category == "graphql"
    assert intros[0].severity == "info"


def test_batching_accepted_emits_candidate():
    m = _module(batched_queries=True)
    out = m.discover(include_probes=False)
    batch = [c for c in out if c.finding_type == "graphql_batching_accepted"]
    assert len(batch) == 1
    assert "DoS amplification" in batch[0].detail


def test_suggestions_enabled_emits_candidate():
    m = _module(suggestions_supported=True)
    out = m.discover(include_probes=False)
    sugg = [c for c in out if c.finding_type == "graphql_suggestions_enabled"]
    assert len(sugg) == 1
    assert "schema oracle" in sugg[0].detail


def test_no_profile_observations_no_candidates():
    m = _module()
    out = m.discover(include_probes=False, include_fuzz=False)
    assert out == []


def test_all_three_observations_emit_three_candidates():
    m = _module(
        introspection_enabled=True,
        batched_queries=True,
        suggestions_supported=True,
        type_count=10,
    )
    out = m.discover(include_probes=False, include_fuzz=False)
    assert len(out) == 3


def test_depth_above_threshold_emits_candidate():
    m = _module()
    with (
        patch(
            "janissary.integrations.graphql_discovery.depth_probe",
            return_value=(20, ""),
        ),
        patch(
            "janissary.integrations.graphql_discovery.alias_probe",
            return_value=(None, ""),
        ),
    ):
        out = m.discover(include_probes=True, include_fuzz=False)
    depth = [c for c in out if c.finding_type == "graphql_depth_abuse"]
    assert len(depth) == 1
    assert "20" in depth[0].detail


def test_depth_below_threshold_no_candidate():
    m = _module()
    with (
        patch(
            "janissary.integrations.graphql_discovery.depth_probe",
            return_value=(5, "refused"),
        ),
        patch(
            "janissary.integrations.graphql_discovery.alias_probe",
            return_value=(None, ""),
        ),
    ):
        out = m.discover(include_probes=True, include_fuzz=False)
    assert [c for c in out if c.finding_type == "graphql_depth_abuse"] == []


def test_alias_above_threshold_emits_candidate():
    m = _module()
    with (
        patch(
            "janissary.integrations.graphql_discovery.depth_probe",
            return_value=(None, ""),
        ),
        patch(
            "janissary.integrations.graphql_discovery.alias_probe",
            return_value=(500, ""),
        ),
    ):
        out = m.discover(include_probes=True, include_fuzz=False)
    alias = [c for c in out if c.finding_type == "graphql_alias_abuse"]
    assert len(alias) == 1
    assert "500" in alias[0].detail


def test_alias_below_threshold_no_candidate():
    m = _module()
    with (
        patch(
            "janissary.integrations.graphql_discovery.depth_probe",
            return_value=(None, ""),
        ),
        patch(
            "janissary.integrations.graphql_discovery.alias_probe",
            return_value=(50, "refused"),
        ),
    ):
        out = m.discover(include_probes=True, include_fuzz=False)
    assert [c for c in out if c.finding_type == "graphql_alias_abuse"] == []


def test_fuzz_error_response_emits_candidate():
    schema = {
        "types": [
            {
                "name": "Query",
                "fields": [
                    {"name": "user", "args": [{"name": "id"}]},
                ],
            }
        ]
    }
    m = _module(query_type="Query", schema=schema)
    fake_result = FuzzResult(
        field="user",
        arg="id",
        payload_name="sqli_quote",
        payload_value="'",
        status=500,
        elapsed=0.1,
        errors=["SQL syntax error"],
        data=None,
        body={"errors": [{"message": "SQL syntax error"}]},
    )
    with (
        patch(
            "janissary.integrations.graphql_discovery.depth_probe",
            return_value=(None, ""),
        ),
        patch(
            "janissary.integrations.graphql_discovery.alias_probe",
            return_value=(None, ""),
        ),
        patch(
            "janissary.integrations.graphql_discovery.fuzz_arguments",
            return_value=[fake_result],
        ),
    ):
        out = m.discover(include_probes=False, include_fuzz=True)
    fuzz = [c for c in out if c.finding_type == "graphql_argument_fuzz_error"]
    assert len(fuzz) == 1
    assert "SQL syntax error" in fuzz[0].detail
    assert "user" in fuzz[0].detail
    assert "id" in fuzz[0].detail


def test_fuzz_clean_response_no_candidate():
    schema = {
        "types": [
            {
                "name": "Query",
                "fields": [
                    {"name": "user", "args": [{"name": "id"}]},
                ],
            }
        ]
    }
    m = _module(query_type="Query", schema=schema)
    clean = FuzzResult(
        field="user",
        arg="id",
        payload_name="sqli_quote",
        payload_value="'",
        status=200,
        elapsed=0.05,
        errors=[],
        data={"user": {"id": "1"}},
        body={"data": {"user": {"id": "1"}}},
    )
    with (
        patch(
            "janissary.integrations.graphql_discovery.depth_probe",
            return_value=(None, ""),
        ),
        patch(
            "janissary.integrations.graphql_discovery.alias_probe",
            return_value=(None, ""),
        ),
        patch(
            "janissary.integrations.graphql_discovery.fuzz_arguments",
            return_value=[clean],
        ),
    ):
        out = m.discover(include_probes=False, include_fuzz=True)
    assert [c for c in out if c.finding_type == "graphql_argument_fuzz_error"] == []


def test_enumerate_fuzz_targets_extracts_field_arg_pairs():
    schema = {
        "types": [
            {
                "name": "Query",
                "fields": [
                    {"name": "user", "args": [{"name": "id"}]},
                    {"name": "posts", "args": [{"name": "limit"}, {"name": "offset"}]},
                    {"name": "__typename", "args": []},  # skipped: __ prefix
                ],
            },
            {
                "name": "User",
                "fields": [{"name": "email", "args": []}],
            },  # skipped: not query root
        ]
    }
    m = _module(query_type="Query", schema=schema)
    targets = m._enumerate_fuzz_targets(max_targets=None)
    assert targets == [("user", "id"), ("posts", "limit"), ("posts", "offset")]


def test_enumerate_fuzz_targets_respects_max():
    schema = {
        "types": [
            {
                "name": "Query",
                "fields": [
                    {"name": "a", "args": [{"name": "x"}]},
                    {"name": "b", "args": [{"name": "y"}]},
                    {"name": "c", "args": [{"name": "z"}]},
                ],
            }
        ]
    }
    m = _module(query_type="Query", schema=schema)
    targets = m._enumerate_fuzz_targets(max_targets=2)
    assert len(targets) == 2


def test_discover_with_no_probes_no_fuzz_returns_only_profile_observations():
    m = _module(introspection_enabled=True, type_count=5)
    out = m.discover(include_probes=False, include_fuzz=False)
    assert len(out) == 1
    assert out[0].finding_type == "graphql_introspection_enabled"


def test_all_finding_types_have_graphql_prefix():
    m = _module(
        introspection_enabled=True,
        batched_queries=True,
        suggestions_supported=True,
        type_count=10,
    )
    with (
        patch(
            "janissary.integrations.graphql_discovery.depth_probe",
            return_value=(20, ""),
        ),
        patch(
            "janissary.integrations.graphql_discovery.alias_probe",
            return_value=(500, ""),
        ),
    ):
        out = m.discover(include_probes=True, include_fuzz=False)
    assert out
    for c in out:
        assert c.finding_type.startswith("graphql_"), (
            f"finding_type must be prefixed with graphql_; got {c.finding_type!r}"
        )


def test_depth_uses_schema_derived_path_when_available():
    """FN-18: when schema has a self-referencing path, depth_probe receives
    the derived field name and path= argument, not __typename."""
    from unittest.mock import patch as _p

    schema = {
        "queryType": {"name": "Query"},
        "types": [
            {
                "name": "Query",
                "fields": [
                    {
                        "name": "currentUser",
                        "args": [],
                        "type": {"kind": "OBJECT", "name": "User"},
                    },
                ],
            },
            {
                "name": "User",
                "fields": [
                    {
                        "name": "friend",
                        "args": [],
                        "type": {"kind": "OBJECT", "name": "User"},
                    },
                ],
            },
        ],
    }
    m = _module(query_type="Query", schema=schema)

    captured = {}

    def fake_depth(client, field_name="__typename", path=None, **kw):
        captured["field_name"] = field_name
        captured["path"] = path
        return (20, "")

    with (
        _p("janissary.integrations.graphql_discovery.depth_probe", fake_depth),
        _p(
            "janissary.integrations.graphql_discovery.alias_probe",
            return_value=(None, ""),
        ),
    ):
        out = m.discover(include_probes=True, include_fuzz=False)

    assert captured["field_name"] == "friend"
    assert captured["path"] == "currentUser"
    depth = [c for c in out if c.finding_type == "graphql_depth_abuse"]
    assert len(depth) == 1
    assert "currentUser.friend" in depth[0].detail


def test_depth_falls_back_when_no_self_ref_path():
    """FN-18: no self-ref path in schema -> depth not tested, no false claim."""
    from unittest.mock import patch as _p

    schema = {
        "queryType": {"name": "Query"},
        "types": [
            {
                "name": "Query",
                "fields": [
                    {
                        "name": "user",
                        "args": [],
                        "type": {"kind": "OBJECT", "name": "User"},
                    },
                ],
            },
            {
                "name": "User",
                "fields": [
                    {
                        "name": "name",
                        "args": [],
                        "type": {"kind": "SCALAR", "name": "String"},
                    },
                ],
            },
        ],
    }
    m = _module(query_type="Query", schema=schema)

    with (
        _p(
            "janissary.integrations.graphql_discovery.depth_probe",
            return_value=(None, "validation error"),
        ),
        _p(
            "janissary.integrations.graphql_discovery.alias_probe",
            return_value=(None, ""),
        ),
    ):
        out = m.discover(include_probes=True, include_fuzz=False)

    depth = [c for c in out if c.finding_type == "graphql_depth_abuse"]
    assert depth == []


def test_depth_fires_with_derived_path_above_threshold():
    """FN-18: derived path + depth above threshold -> finding fires."""
    from unittest.mock import patch as _p

    schema = {
        "queryType": {"name": "Query"},
        "types": [
            {
                "name": "Query",
                "fields": [
                    {
                        "name": "me",
                        "args": [],
                        "type": {"kind": "OBJECT", "name": "User"},
                    },
                ],
            },
            {
                "name": "User",
                "fields": [
                    {
                        "name": "friend",
                        "args": [],
                        "type": {"kind": "OBJECT", "name": "User"},
                    },
                ],
            },
        ],
    }
    m = _module(query_type="Query", schema=schema)

    with (
        _p(
            "janissary.integrations.graphql_discovery.depth_probe",
            return_value=(25, ""),
        ),
        _p(
            "janissary.integrations.graphql_discovery.alias_probe",
            return_value=(None, ""),
        ),
    ):
        out = m.discover(include_probes=True, include_fuzz=False)

    depth = [c for c in out if c.finding_type == "graphql_depth_abuse"]
    assert len(depth) == 1
    assert "25" in depth[0].detail


def test_build_wrapped_nested_query_ends_with_typename_leaf():
    """FN-18 follow-up: without __typename terminator, object-typed field
    selections are invalid GraphQL at every depth. This pins the leaf."""
    from janissary.integrations.graphql import build_wrapped_nested_query

    q1 = build_wrapped_nested_query("currentUser", "friend", 1)
    assert "__typename" in q1
    assert q1.count("friend") == 1
    assert q1 == "{ currentUser { friend { __typename } } }"

    q3 = build_wrapped_nested_query("currentUser", "friend", 3)
    assert "__typename" in q3
    assert q3.count("friend") == 3
    assert q3 == "{ currentUser { friend { friend { friend { __typename } } } } }"
