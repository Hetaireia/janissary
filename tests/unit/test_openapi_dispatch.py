"""Stage 5: parameter location tracking and scan-target dispatch (ADR-030).

Red before parameter_locations exists on Operation and before
dispatch.build_scan_targets exists. Expected first red is a collection
ImportError from the dispatch import, not assertion failures.

Dispatch returns one target per distinct parameter location: an
operation with a path param, a query param, and a header param yields
three targets, because Scanner.inject_in is a single mode per scanner.
"""

import json

from janissary.importers.dispatch import build_scan_targets
from janissary.importers.openapi import Operation, parse_spec


def _write(tmp_path, spec):
    p = tmp_path / "spec.json"
    p.write_text(json.dumps(spec), encoding="utf8")
    return p


def test_parameter_locations_populated(tmp_path):
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1.0"},
        "paths": {
            "/pets/{petId}": {
                "get": {
                    "operationId": "g",
                    "parameters": [
                        {"name": "petId", "in": "path", "required": True},
                        {"name": "limit", "in": "query"},
                    ],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    result = parse_spec(_write(tmp_path, spec))
    op = result.imported[0]
    assert op.parameter_locations == {"petId": "path", "limit": "query"}


def test_parameter_locations_skips_unsupported(tmp_path):
    spec = {
        "swagger": "2.0",
        "info": {"title": "t", "version": "1.0"},
        "paths": {
            "/upload": {
                "post": {
                    "operationId": "up",
                    "parameters": [{"name": "file", "in": "formData", "type": "file"}],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    result = parse_spec(_write(tmp_path, spec))
    op = result.imported[0]
    assert "file" not in op.parameter_locations
    assert any("formData" in n for n in result.notes)


def test_dispatch_single_query_location():
    op = Operation(
        path="/pets",
        method="get",
        parameter_names=["limit"],
        parameter_locations={"limit": "query"},
        base_url="https://api.example.com",
    )
    targets = build_scan_targets(op)
    assert len(targets) == 1
    assert targets[0]["inject_in"] == "query"
    assert targets[0]["params"] == ["limit"]
    assert targets[0]["url"] == "https://api.example.com/pets"


def test_dispatch_mixed_locations():
    op = Operation(
        path="/pets/{petId}",
        method="get",
        parameter_names=["petId", "limit", "X-Api-Key"],
        parameter_locations={
            "petId": "path",
            "limit": "query",
            "X-Api-Key": "header",
        },
        base_url="https://api.example.com",
    )
    targets = build_scan_targets(op)
    assert len(targets) == 3
    modes = sorted(t["inject_in"] for t in targets)
    assert modes == ["header", "path", "query"]


def test_dispatch_no_parameters():
    op = Operation(
        path="/health",
        method="get",
        base_url="https://api.example.com",
    )
    targets = build_scan_targets(op)
    assert len(targets) == 1
    assert targets[0]["inject_in"] == "auto"
    assert targets[0]["params"] == []
    assert targets[0]["url"] == "https://api.example.com/health"


def test_dispatch_body_location():
    """Body params are not injected by name: Stage 5 limitation.

    Before the amendment this asserted inject_in == "json-body", which
    Scanner.__init__ rejects without a json_template. A body target now
    scans the endpoint in "auto" mode with no named params and carries a
    note. Consumption is tested in test_openapi_dispatch_consumption.py.
    """
    op = Operation(
        path="/pets",
        method="post",
        parameter_names=["body"],
        parameter_locations={"body": "body"},
        base_url="https://api.example.com",
    )
    targets = build_scan_targets(op)
    assert len(targets) == 1
    assert targets[0]["inject_in"] == "auto"
    assert targets[0]["params"] == []
    assert "note" in targets[0]
