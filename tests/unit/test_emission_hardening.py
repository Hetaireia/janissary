"""M77b: _VerifiedFindingsList.__setitem__ and .insert enforce the invariant.

Before this, append and extend validated _engine_emitted, but __setitem__
and insert delegated directly to list's implementation. Slice assignment
in particular could replace a validated finding with a raw ScanFinding
that had never passed through VerificationEngine.verify() ->
_to_scan_finding(), silently defeating the Phase 0.1 emission boundary.

_DedupedFindingsList inherits the check because its __setitem__ calls
super().__setitem__.
"""

from __future__ import annotations

import pytest

from janissary.engine.scanner import (
    ScanFinding,
    _DedupedFindingsList,
    _VerifiedFindingsList,
)


def _finding(fp=None):
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
    if fp is not None:
        f.fingerprint = fp
    return f


def _raw_finding():
    return ScanFinding(
        param="p",
        payload_name="x",
        payload_value="y",
        category="sqli",
        severity="high",
        finding_type="test",
        detail="d",
    )


def test_setitem_rejects_non_engine_emitted():
    lst = _VerifiedFindingsList()
    lst.append(_finding())
    with pytest.raises(AssertionError, match=r"Phase 0\.1"):
        lst[0] = _raw_finding()


def test_setitem_accepts_engine_emitted():
    lst = _VerifiedFindingsList()
    lst.append(_finding())
    lst[0] = _finding()
    assert len(lst) == 1


def test_setitem_slice_rejects_any_non_engine_emitted():
    lst = _VerifiedFindingsList()
    lst.append(_finding())
    with pytest.raises(AssertionError, match=r"Phase 0\.1"):
        lst[0:1] = [_finding(), _raw_finding()]


def test_insert_rejects_non_engine_emitted():
    lst = _VerifiedFindingsList()
    with pytest.raises(AssertionError, match=r"Phase 0\.1"):
        lst.insert(0, _raw_finding())


def test_deduped_list_setitem_inherits_validation():
    lst = _DedupedFindingsList()
    lst.append(_finding("fp-a"))
    with pytest.raises(AssertionError, match=r"Phase 0\.1"):
        lst[0] = _raw_finding()
