"""Stage 2 ref resolution tests (ADR-030).

Red before the resolver lands. Both are silent-drop classes: the
operation count can stay green while names or whole operations
vanish without a SkipRecord.
"""
import json
from pathlib import Path

from janissary.importers.openapi import parse_spec

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "openapi"
EXTERNAL_REF = FIXTURES_DIR / "external-ref-3.0.json"


def _write(tmp_path, spec):
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(spec), encoding="utf8")
    return p


def test_parameter_ref_resolves_name(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/pets/{petId}": {
                "get": {
                    "operationId": "g",
                    "parameters": [{"$ref": "#/components/parameters/PetId"}],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
        "components": {
            "parameters": {
                "PetId": {
                    "name": "petId",
                    "in": "path",
                    "required": True,
                    "schema": {"type": "integer"},
                }
            }
        },
    }
    result = parse_spec(_write(tmp_path, spec))
    assert len(result.imported) == 1
    assert result.imported[0].parameter_names == ["petId"]


def test_path_item_ref_is_not_silently_dropped(tmp_path):
    spec = {
        "openapi": "3.0.0",
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


def test_external_ref_fixture_parses():
    result = parse_spec(EXTERNAL_REF)
    assert len(result.imported) == 1
    assert result.imported[0].path == "/pets/{petId}"
    assert result.imported[0].method == "get"
    assert result.imported[0].parameter_names == ["petId"]
    assert result.skipped == []
