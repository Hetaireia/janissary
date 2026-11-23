"""D-7 (ADR-036) invariants: request counts carry provenance.

Five invariants, per ADR-036 Decision 7. If any of these regress, the
measured/estimated split has been broken and every downstream denominator
is suspect again.
"""

import pytest

from janissary.engine.scanner import ScanSummary
from janissary.engine.summary_merge import merge_scan_summaries


def _summary() -> ScanSummary:
    return ScanSummary(target="https://example.test", params=["q"], method="GET")


def test_total_is_sum_of_measured_and_estimated():
    s = _summary()
    s.requests_measured += 7
    s.record_estimate("baseline", 3)
    assert s.total_requests == 10
    assert s.total_requests == s.requests_measured + s.requests_estimated


def test_approximate_requests_aliases_estimated():
    s = _summary()
    s.record_estimate("waf_probe", 5)
    assert s.approximate_requests == s.requests_estimated == 5


def test_total_requests_is_read_only():
    s = _summary()
    with pytest.raises(AttributeError):
        s.total_requests = 5
    with pytest.raises(AttributeError):
        s.approximate_requests = 5


def test_unknown_estimate_source_raises():
    s = _summary()
    with pytest.raises(ValueError):
        s.record_estimate("not_a_source", 1)
    assert s.requests_estimated == 0


def test_merge_sums_breakdown_per_key():
    a = _summary()
    b = _summary()
    a.record_estimate("baseline", 2)
    a.record_estimate("waf_probe", 1)
    b.record_estimate("baseline", 4)
    merged = merge_scan_summaries([a, b])
    assert merged.requests_estimated_breakdown["baseline"] == 6
    assert merged.requests_estimated_breakdown["waf_probe"] == 1
    assert merged.requests_estimated == 7
