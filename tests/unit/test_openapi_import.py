"""Tests for the Stage 1 OpenAPI parser (ADR 030).

Covers the silent drop invariant: every operation either imports or
lands in skipped with a reason. Differential checks against the
committed expected count files, which Commit A verified against prance.
"""

import json
from pathlib import Path

import pytest

from janissary.importers.openapi import OpenAPIImportError, parse_spec

HY = "-"


def _find_fixtures_dir():
    tail = ("tests", "fixtures", "openapi")
    here = Path(__file__).resolve()
    candidates = [here, *here.parents, Path.cwd()]
    for base in candidates:
        candidate = base / Path(*tail)
        if candidate.is_dir():
            return candidate
    raise RuntimeError(
        "could not locate openapi fixtures dir; file="
        + str(here)
        + " cwd="
        + str(Path.cwd())
    )


FIXTURES_DIR = _find_fixtures_dir()
PETSTORE = FIXTURES_DIR / ("petstore" + HY + "3.0.json")
USPTO = FIXTURES_DIR / ("uspto" + HY + "api" + HY + "3.0.json")
PETSTORE_EXPECTED = FIXTURES_DIR / ("petstore" + HY + "3.0.expected.json")
USPTO_EXPECTED = FIXTURES_DIR / ("uspto" + HY + "api" + HY + "3.0.expected.json")


def test_petstore_import_count():
    result = parse_spec(PETSTORE)
    assert len(result.imported) == 3
    assert len(result.skipped) == 0
    assert result.total == 3


def test_uspto_import_count():
    result = parse_spec(USPTO)
    assert len(result.imported) == 3
    assert len(result.skipped) == 0
    assert result.total == 3


def test_agrees_with_prance_petstore():
    result = parse_spec(PETSTORE)
    expected = json.loads(PETSTORE_EXPECTED.read_text(encoding="utf8"))
    assert result.total == expected["operations"]


def test_agrees_with_prance_uspto():
    result = parse_spec(USPTO)
    expected = json.loads(USPTO_EXPECTED.read_text(encoding="utf8"))
    assert result.total == expected["operations"]


def test_petstore_operation_shape():
    result = parse_spec(PETSTORE)
    keys = {(o.path, o.method) for o in result.imported}
    assert ("/pets", "get") in keys
    assert ("/pets", "post") in keys
    assert ("/pets/{petId}", "get") in keys


def test_petstore_parameter_names():
    result = parse_spec(PETSTORE)
    by_key = {(o.path, o.method): o for o in result.imported}
    pet_by_id = by_key[("/pets/{petId}", "get")]
    assert "petId" in pet_by_id.parameter_names
    list_pets = by_key[("/pets", "get")]
    assert "limit" in list_pets.parameter_names
    create_pets = by_key[("/pets", "post")]
    assert create_pets.parameter_names == []


def test_rejects_non_3_0(tmp_path):
    spec = {"openapi": "2.0", "paths": {}}
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(spec), encoding="utf8")
    with pytest.raises(OpenAPIImportError):
        parse_spec(p)


def test_rejects_missing_paths(tmp_path):
    spec = {"openapi": "3.0.0"}
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(spec), encoding="utf8")
    with pytest.raises(OpenAPIImportError):
        parse_spec(p)


def test_rejects_invalid_json(tmp_path):
    p = tmp_path / "spec.json"
    p.write_text("this is not json {", encoding="utf8")
    with pytest.raises(OpenAPIImportError):
        parse_spec(p)


def test_rejects_missing_file(tmp_path):
    p = tmp_path / "missing.json"
    assert not p.exists()
    with pytest.raises(OpenAPIImportError):
        parse_spec(p)


def test_skips_malformed_operation(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/good": {"get": {"operationId": "ok"}},
            "/bad": {"post": "this is not an object"},
        },
    }
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(spec), encoding="utf8")
    result = parse_spec(p)
    assert len(result.imported) == 1
    assert len(result.skipped) == 1
    assert result.total == 2
    assert result.skipped[0].path == "/bad"
    assert result.skipped[0].method == "post"
    assert result.skipped[0].reason
