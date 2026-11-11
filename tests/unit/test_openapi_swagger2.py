"""Stage 3: Swagger 2.0 acceptance tests (ADR-030).

Red before the version gate is relaxed: _validate rejects anything
that is not 3.0.x. These inline specs are the minimum needed to prove
acceptance and ref resolution, not full 2.0 coverage.
"""

import json

from janissary.importers.openapi import parse_spec


def _write(tmp_path, spec):
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(spec), encoding="utf8")
    return p


def test_swagger_2_0_accepted(tmp_path):
    spec = {
        "swagger": "2.0",
        "info": {"title": "tiny", "version": "1.0"},
        "paths": {
            "/ping": {
                "get": {
                    "operationId": "ping",
                    "parameters": [{"name": "q", "in": "query", "type": "string"}],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    result = parse_spec(_write(tmp_path, spec))
    assert len(result.imported) == 1
    assert result.imported[0].path == "/ping"
    assert result.imported[0].method == "get"
    assert result.imported[0].parameter_names == ["q"]
    assert result.skipped == []
    assert result.spec_version == "swagger 2.0"


def test_swagger_2_0_path_item_ref(tmp_path):
    spec = {
        "swagger": "2.0",
        "info": {"title": "tiny", "version": "1.0"},
        "paths": {
            "/a": {"$ref": "#/paths/~1b"},
            "/b": {
                "get": {
                    "operationId": "b",
                    "responses": {"200": {"description": "ok"}},
                }
            },
        },
    }
    result = parse_spec(_write(tmp_path, spec))
    keys = {(o.path, o.method) for o in result.imported}
    assert ("/b", "get") in keys
    assert ("/a", "get") in keys
    assert result.skipped == []


def test_swagger_2_0_parameter_ref(tmp_path):
    spec = {
        "swagger": "2.0",
        "info": {"title": "tiny", "version": "1.0"},
        "paths": {
            "/x": {
                "get": {
                    "operationId": "x",
                    "parameters": [{"$ref": "#/parameters/CommonQ"}],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
        "parameters": {"CommonQ": {"name": "q", "in": "query", "type": "string"}},
    }
    result = parse_spec(_write(tmp_path, spec))
    assert len(result.imported) == 1
    assert result.imported[0].parameter_names == ["q"]
