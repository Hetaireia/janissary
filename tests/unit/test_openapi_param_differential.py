"""Parameter-name differential against prance (ADR-030 test strategy).

For every fixture, asserts JANISSARY's parser and prance agree on the
set of operation keys and the sorted parameter names per operation.
"""
from pathlib import Path

import pytest
from prance import ResolvingParser

from janissary.importers.openapi import parse_spec

BACKEND = "openapi-spec-validator"
METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


def _find_fixtures_dir():
    tail = ("tests", "fixtures", "openapi")
    here = Path(__file__).resolve()
    candidates = [here, *here.parents, Path.cwd()]
    for base in candidates:
        candidate = base / Path(*tail)
        if candidate.is_dir():
            return candidate
    raise RuntimeError(
        "could not locate openapi fixtures dir; file=" + str(here)
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


def prance_params(fixture):
    parser = ResolvingParser(
        str(fixture), backend=BACKEND, recursion_limit=5
    )
    spec = parser.specification
    out = {}
    for path, item in spec.get("paths", {}).items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            m = str(method).lower()
            if m not in METHODS or not isinstance(op, dict):
                continue
            names = sorted(
                q.get("name")
                for q in op.get("parameters", [])
                if isinstance(q, dict) and q.get("name")
            )
            out[(path, m)] = names
    return out


def janissary_params(fixture):
    result = parse_spec(fixture)
    return {
        (op.path, op.method): sorted(op.parameter_names)
        for op in result.imported
    }


@pytest.mark.parametrize("fixture", fixtures(), ids=lambda p: p.name)
def test_parameter_names_agree(fixture):
    expected = prance_params(fixture)
    actual = janissary_params(fixture)
    assert actual == expected
