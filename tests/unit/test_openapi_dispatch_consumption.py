"""ADR-030 Stage 5: every dispatch target must construct a Scanner.

The existing test_openapi_dispatch.py exercises emission only. dispatch.py
deliberately avoids importing Scanner ("no scanner import, no network, no
I/O") -- correct for the module, but it left the join untested.
build_scan_targets emitted inject_in="json-body" with json_template=None;
Scanner.__init__ raises ValueError on exactly that combination. Six
dispatch tests passed while the crash sat one function call away.

These tests construct the Scanner Stage 6 will construct. They scan
nothing, hit no network, and need no live target.
"""
from janissary.engine.scanner import Scanner
from janissary.importers.dispatch import build_scan_targets
from janissary.importers.openapi import Operation


def _op(path, method, names, locations, base_url="http://example.test"):
    return Operation(
        path=path,
        method=method,
        operation_id="op",
        parameter_names=list(names),
        parameter_locations=dict(locations),
        base_url=base_url,
    )


def _construct(target):
    """Exactly the call Stage 6 makes. Must not raise."""
    return Scanner(
        target=target["url"],
        params=target["params"],
        method=target["method"],
        inject_in=target["inject_in"],
        json_template=target["json_template"],
    )


def test_path_target_constructs_scanner():
    op = _op("/pets/{petId}", "GET", ["petId"], {"petId": "path"})
    for t in build_scan_targets(op):
        _construct(t)


def test_query_target_constructs_scanner():
    op = _op("/pets", "GET", ["limit"], {"limit": "query"})
    for t in build_scan_targets(op):
        _construct(t)


def test_header_target_constructs_scanner():
    op = _op("/pets", "GET", ["X-Trace"], {"X-Trace": "header"})
    for t in build_scan_targets(op):
        _construct(t)


def test_cookie_target_constructs_scanner():
    op = _op("/pets", "GET", ["sid"], {"sid": "cookie"})
    for t in build_scan_targets(op):
        _construct(t)


def test_body_target_constructs_scanner():
    """The defect this file was written for.

    Before the Stage 5 amendment: body targets carried
    inject_in="json-body" with json_template=None, and Scanner.__init__
    raises ValueError("inject_in='json-body' requires json_template").
    """
    op = _op("/pets", "POST", ["body"], {"body": "body"})
    targets = build_scan_targets(op)
    body = [t for t in targets if t["location"] == "body"]
    assert len(body) == 1, "expected exactly one body target"
    _construct(body[0])
    assert "note" in body[0], "body target must carry a limitation note"


def test_parameterless_target_constructs_scanner():
    op = _op("/health", "GET", [], {})
    targets = build_scan_targets(op)
    assert len(targets) == 1
    assert targets[0]["location"] == "none"
    _construct(targets[0])


def test_mixed_operation_all_targets_construct():
    op = _op(
        "/pets/{petId}",
        "POST",
        ["petId", "limit", "X-Trace", "body"],
        {"petId": "path", "limit": "query", "X-Trace": "header", "body": "body"},
    )
    targets = build_scan_targets(op)
    assert len(targets) == 4
    for t in targets:
        _construct(t)
