"""Stage 6: _build_scanner constructs a Scanner from a dispatch target.

One layer above test_openapi_dispatch_consumption: that file proves
Scanner.__init__ accepts every target build_scan_targets emits. This
proves the CLI helper the per-target loop will call does too -- same
contract, one step closer to the loop.

Assertions are limited to attributes verified by reading scanner.py:
self.params and self.inject_in.
"""

import argparse
from types import SimpleNamespace

from janissary.cli import _build_scanner
from janissary.importers.dispatch import build_scan_targets
from janissary.importers.openapi import Operation


def _auth_cfg():
    return SimpleNamespace(is_empty=True, sessions=[])


def _args(**over):
    ns = argparse.Namespace(
        timeout=10.0,
        baseline_count=10,
        delay=0.0,
        stealth=False,
        no_waf=False,
        baseline_value="",
        json_template=None,
    )
    for k, v in over.items():
        setattr(ns, k, v)
    return ns


def _op(path, method, names, locations, base_url="http://example.test"):
    return Operation(
        path=path,
        method=method,
        operation_id="op",
        parameter_names=list(names),
        parameter_locations=dict(locations),
        base_url=base_url,
    )


def _build(target, args=None):
    return _build_scanner(
        args or _args(),
        target=target["url"],
        params=target["params"],
        method=target["method"],
        inject_in=target["inject_in"],
        proxies=None,
        session=None,
        collaborator=None,
        auth_cfg=_auth_cfg(),
        json_template=target["json_template"],
    )


def test_build_scanner_query_target():
    op = _op("/pets", "GET", ["limit"], {"limit": "query"})
    for t in build_scan_targets(op):
        s = _build(t)
        assert s.inject_in == "param-name"
        assert s.params == t["params"]


def test_build_scanner_body_target():
    op = _op("/pets", "POST", ["body"], {"body": "body"})
    for t in build_scan_targets(op):
        s = _build(t)
        assert s.inject_in == "auto"
        assert s.params == []


def test_build_scanner_mixed_operation_all_targets():
    op = _op(
        "/pets/{petId}",
        "POST",
        ["petId", "limit", "X-Trace", "body"],
        {"petId": "path", "limit": "query", "X-Trace": "header", "body": "body"},
    )
    targets = build_scan_targets(op)
    assert len(targets) == 4
    for t in targets:
        s = _build(t)
        assert s.inject_in == t["inject_in"]
        assert s.params == t["params"]


def test_build_scanner_parameterless_target():
    op = _op("/health", "GET", [], {})
    for t in build_scan_targets(op):
        s = _build(t)
        assert s.inject_in == "auto"
        assert s.params == []
