"""Differential oracle self-check for OpenAPI fixtures.

No JANISSARY parser code yet. This asserts that prance, the reference
implementation, agrees with the committed expected counts. When the
Stage 1 parser lands, these counts become its target.
"""
import json
from pathlib import Path

import pytest
from prance import ResolvingParser

BACKEND = "openapi-spec-validator"
METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


def _find_fixtures_dir():
    tail = ("tests", "fixtures", "openapi")
    here = Path("__file__").resolve()
    candidates = [here, *here.parents, Path.cwd()]
    for base in candidates:
        candidate = base / Path(*tail)
        if candidate.is_dir():
            return candidate
    raise RuntimeError(
        "could not locate openapi fixtures dir; file=" + str(here)
        + " cwd=" + str(Path.cwd())
    )


FIXTURES_DIR = _find_fixtures_dir()


def fixtures():
    found = sorted(
        p for p in FIXTURES_DIR.iterdir()
        if p.suffix == ".json" and not p.name.endswith(".expected.json")
    )
    if not found:
        raise RuntimeError("no .json fixtures in " + str(FIXTURES_DIR))
    return found


def count_operations(spec):
    paths = 0
    ops = 0
    for path, item in spec.get("paths", {}).items():
        n = sum(1 for m in item.keys() if m.lower() in METHODS)
        if n:
            paths += 1
            ops += n
    return paths, ops


@pytest.mark.parametrize("fixture", fixtures(), ids=lambda p: p.name)
def test_prance_parses_fixture(fixture):
    parser = ResolvingParser(str(fixture), backend=BACKEND, recursion_limit=5)
    spec = parser.specification
    assert isinstance(spec, dict)
    assert "openapi" in spec
    assert spec["openapi"].startswith("3.0.")


@pytest.mark.parametrize("fixture", fixtures(), ids=lambda p: p.name)
def test_prance_count_matches_expected(fixture):
    expected_path = fixture.with_name(fixture.name[:-5] + ".expected.json")
    assert expected_path.exists()
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    parser = ResolvingParser(str(fixture), backend=BACKEND, recursion_limit=5)
    paths, ops = count_operations(parser.specification)
    assert paths == expected["paths"]
    assert ops == expected["operations"]
