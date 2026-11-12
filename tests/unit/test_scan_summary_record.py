"""M77a: ScanSummary.record() gates finding_count on append success.

Before this fix, every site that appended to summary.findings also did
an unconditional `finding_count += 1`. _DedupedFindingsList silently
drops duplicate fingerprints, so the count could exceed len(findings).

record() closes that gap: append returns True/False, and count only
increments on True.
"""

from __future__ import annotations

from janissary.engine.scanner import ScanFinding, ScanSummary


def _finding(fp="fp-1"):
    f = ScanFinding(
        param="p",
        payload_name="x",
        payload_value="y",
        category="sqli",
        severity="high",
        finding_type="test",
        detail="d",
    )
    f._engine_emitted = True
    f.fingerprint = fp
    return f


def _summary():
    return ScanSummary(target="http://x/", params=["p"], method="GET")


def test_record_increments_count():
    s = _summary()
    s.record(_finding("fp-a"))
    assert s.finding_count == 1
    assert len(s.findings) == 1


def test_record_returns_true_on_add():
    s = _summary()
    assert s.record(_finding("fp-b")) is True


def test_record_returns_false_on_duplicate_fingerprint():
    s = _summary()
    s.record(_finding("fp-c"))
    assert s.record(_finding("fp-c")) is False


def test_record_does_not_increment_count_on_duplicate():
    s = _summary()
    s.record(_finding("fp-d"))
    s.record(_finding("fp-d"))
    assert s.finding_count == 1
    assert len(s.findings) == 1


def test_count_matches_len_after_mixed_operations():
    s = _summary()
    s.record(_finding("fp-1"))
    s.record(_finding("fp-2"))
    s.record(_finding("fp-1"))  # duplicate, ignored
    s.record(_finding("fp-3"))
    assert s.finding_count == 3
    assert len(s.findings) == 3
    assert s.finding_count == len(s.findings)
