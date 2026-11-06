"""Fingerprint-based dedup of ScanSummary.findings (ADR-007 identity)."""

from __future__ import annotations

from janissary.engine.scanner import (
    ScanFinding,
    ScanSummary,
    _DedupedFindingsList,
    _VerifiedFindingsList,
)


def _make(fp, payload="p"):
    f = ScanFinding(
        param="q",
        payload_name="test",
        payload_value=payload,
        category="sqli",
        severity="critical",
        finding_type="error-based",
        detail=f"fingerprint={fp}",
        url="http://x/y",
        method="GET",
    )
    f.fingerprint = fp
    f._engine_emitted = True
    return f


def test_deduped_list_is_verified_list_subclass():
    assert issubclass(_DedupedFindingsList, _VerifiedFindingsList)


def test_same_fingerprint_appended_once():
    lst = _DedupedFindingsList()
    lst.append(_make("jfv1:abc", "'"))
    lst.append(_make("jfv1:abc", '"'))
    lst.append(_make("jfv1:abc", "1' OR '1'='1"))
    assert len(lst) == 1
    assert lst[0].fingerprint == "jfv1:abc"


def test_distinct_fingerprints_all_kept():
    lst = _DedupedFindingsList()
    lst.append(_make("jfv1:abc"))
    lst.append(_make("jfv1:def"))
    lst.append(_make("jfv1:ghi"))
    assert len(lst) == 3


def test_first_payload_wins():
    lst = _DedupedFindingsList()
    lst.append(_make("jfv1:abc", "FIRST"))
    lst.append(_make("jfv1:abc", "SECOND"))
    assert lst[0].payload_value == "FIRST"


def test_fingerprintless_findings_are_kept():
    lst = _DedupedFindingsList()
    lst.append(_make(None))
    lst.append(_make(None))
    assert len(lst) == 2


def test_extend_also_dedupes():
    lst = _DedupedFindingsList()
    lst.extend(
        [
            _make("jfv1:abc", "p1"),
            _make("jfv1:abc", "p2"),
            _make("jfv1:def", "p3"),
        ]
    )
    assert len(lst) == 2


def test_phase_01_invariant_still_enforced():
    lst = _DedupedFindingsList()
    bad = _make("jfv1:abc")
    bad._engine_emitted = False
    try:
        lst.append(bad)
        raise AssertionError("expected AssertionError for non-engine finding")
    except AssertionError as e:
        assert "Phase 0.1 invariant" in str(e)


def test_scan_summary_uses_deduped_list():
    """ScanSummary.findings must default to _DedupedFindingsList.

    We check the dataclass field default rather than constructing a
    summary — no dependency on required/optional field names, and it
    directly tests what we changed (the default_factory).
    """
    import dataclasses

    fields = {f.name: f for f in dataclasses.fields(ScanSummary)}
    assert "findings" in fields
    default_factory = fields["findings"].default_factory
    assert default_factory is _DedupedFindingsList, (
        f"expected _DedupedFindingsList, got {default_factory!r}"
    )


def test_scan_summary_findings_are_deduped_at_runtime():
    """End-to-end: a real ScanSummary rejects duplicate fingerprints."""
    import dataclasses

    fields = {f.name: f for f in dataclasses.fields(ScanSummary)}
    # Build a minimal valid instance using only fields with defaults
    kwargs = {}
    for name, field in fields.items():
        if field.default is not dataclasses.MISSING:
            continue
        if field.default_factory is not dataclasses.MISSING:  # type: ignore[comparison-overlap]
            continue
        # Required field with no default: fill with a benign value
        if name == "target":
            kwargs["target"] = "http://x/"
        elif name == "params":
            kwargs["params"] = ["q"]
        elif field.type in ("int", int):
            kwargs[name] = 0
        elif field.type in ("float", float):
            kwargs[name] = 0.0
        elif field.type in ("str", str):
            kwargs[name] = ""
        else:
            kwargs[name] = None
    summary = ScanSummary(**kwargs)
    summary.findings.append(_make("jfv1:abc", "p1"))
    summary.findings.append(_make("jfv1:abc", "p2"))
    summary.findings.append(_make("jfv1:def", "p3"))
    assert len(summary.findings) == 2
