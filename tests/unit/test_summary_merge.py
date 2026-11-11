"""Merge ScanSummary objects from multiple dispatch targets (ADR-030 Stage 6).

Before Stage 6 there is no generic merge: _merge_graphql_into_scan and
_merge_ws_into_scan in cli.py each do it inline. Both share a latent bug --
finding_count += 1 fires even when the dedupe list silently rejects an
append. The merge here computes finding_count from len(findings) so it
cannot overcount.

The multi-target case is new: one OpenAPI operation with path+query+header
parameters produces three targets, hence three ScanSummary objects that
must aggregate into one before exit code and reporting are derived.
"""

import pytest

from janissary.engine.scanner import ScanFinding, ScanSummary
from janissary.engine.summary_merge import merge_scan_summaries


def _finding(param="p", category="sqli", finding_type="t", url="http://x/a"):
    f = ScanFinding(
        param=param,
        payload_name="pl",
        payload_value="pv",
        category=category,
        severity="high",
        finding_type=finding_type,
        detail="d",
        url=url,
        method="GET",
    )
    f._engine_emitted = True
    return f


def _summary(params, findings=(), total_requests=0, target="http://x/a", method="GET"):
    s = ScanSummary(target=target, params=list(params), method=method)
    for f in findings:
        s.findings.append(f)
    s.finding_count = len(s.findings)
    s.total_requests = total_requests
    return s


def test_merge_two_summaries_findings_and_requests():
    a = _summary(["petId"], [_finding(param="petId")], total_requests=10)
    b = _summary(["limit"], [_finding(param="limit")], total_requests=5)
    merged = merge_scan_summaries([a, b])
    assert merged.total_requests == 15
    assert len(merged.findings) == 2
    assert merged.finding_count == 2


def test_merge_unions_params():
    a = _summary(["petId"])
    b = _summary(["limit"])
    merged = merge_scan_summaries([a, b])
    assert set(merged.params) == {"petId", "limit"}


def test_merge_propagates_scan_incomplete():
    a = _summary(["petId"])
    b = _summary(["limit"])
    b.scan_incomplete = True
    b.abort_reason = "partial"
    merged = merge_scan_summaries([a, b])
    assert merged.scan_incomplete is True
    assert merged.abort_reason == "partial"


def test_merge_propagates_aborted():
    a = _summary(["petId"])
    a.aborted = True
    a.abort_reason = "preflight"
    b = _summary(["limit"])
    merged = merge_scan_summaries([a, b])
    assert merged.aborted is True
    assert merged.abort_reason == "preflight"


def test_merge_baselines_by_param():
    a = _summary(["petId"])
    a.baselines["petId"] = {"samples": 10}
    b = _summary(["limit"])
    b.baselines["limit"] = {"samples": 10}
    merged = merge_scan_summaries([a, b])
    assert set(merged.baselines.keys()) == {"petId", "limit"}


def test_merge_waf_and_pacer_first_non_none():
    a = _summary(["petId"])
    a.waf = {"detected": "modsecurity"}
    a.pacer = {"delay": 0.5}
    b = _summary(["limit"])
    merged = merge_scan_summaries([a, b])
    assert merged.waf == {"detected": "modsecurity"}
    assert merged.pacer == {"delay": 0.5}


def test_merge_dedupes_same_fingerprint():
    f = _finding(param="petId")
    a = _summary(["petId"], [f])
    b = _summary(["petId"], [f])
    merged = merge_scan_summaries([a, b])
    assert len(merged.findings) == 1
    assert merged.finding_count == 1


def test_merge_rejects_empty():
    with pytest.raises(ValueError):
        merge_scan_summaries([])


def test_merge_single_summary_is_fresh_object():
    a = _summary(["petId"], [_finding(param="petId")], total_requests=7)
    merged = merge_scan_summaries([a])
    assert merged is not a
    assert merged.total_requests == 7
    assert len(merged.findings) == 1


def test_merge_recomputes_groups():
    a = _summary(["petId"], [_finding(param="petId")])
    b = _summary(["limit"], [_finding(param="limit")])
    a.groups = ["stale-a"]
    b.groups = ["stale-b"]
    merged = merge_scan_summaries([a, b])
    assert merged.groups != ["stale-a"]
    assert merged.groups != ["stale-b"]
