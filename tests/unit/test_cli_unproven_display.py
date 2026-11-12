"""Display tests for Phase 0.2(b) unproven markers.

A finding with verification_status='unproven' must be visibly marked in
the human CLI output — both at the finding line and at the group header
(if the whole group is unproven). A fully verified finding must not
carry the marker.
"""

from janissary.cli import _print_summary
from janissary.engine.grouping import FindingGroup
from janissary.engine.scanner import ScanFinding, ScanSummary


def _finding(**kw) -> ScanFinding:
    base = {
        "param": "email",
        "payload_name": "sql_single_quote",
        "payload_value": "'",
        "category": "sqli",
        "severity": "high",
        "finding_type": "status_change",
        "detail": "Baseline 401 -> Payload 500",
        "url": "http://x/",
    }
    base.update(kw)
    return ScanFinding(**base)


def _summary_with_group(findings: list[ScanFinding]) -> ScanSummary:
    summary = ScanSummary(target="http://x/", params=["email"], method="POST")
    group = FindingGroup(
        param="email",
        category="sqli",
        root_cause="sql_injection",
        severity="high",
    )
    for f in findings:
        group.add(f)
        if f.verification_status == "unproven":
            summary.candidates.append(f)
        else:
            summary.findings.append(f)
    summary.groups.append(group)
    return summary


def _base(**kw) -> ScanFinding:
    base = {
        "param": "email",
        "payload_name": "sql_single_quote",
        "payload_value": "'",
        "category": "sqli",
        "severity": "high",
        "finding_type": "status_change",
        "detail": "Baseline 401 -> Payload 500",
        "url": "http://x/",
    }
    base.update(kw)
    f = ScanFinding(**base)
    f._engine_emitted = True
    return f


def test_verified_finding_has_no_unproven_marker(capsys):
    f = _base(verification_status="verified", verification_reason=None)
    _print_summary(_summary_with_group([f]))
    out = capsys.readouterr().out
    assert "[unproven]" not in out


def test_unproven_finding_marked_on_line_and_group_header(capsys):
    f = _base(
        verification_status="unproven", verification_reason="corroborator_structural"
    )
    _print_summary(_summary_with_group([f]))
    out = capsys.readouterr().out
    # Group header marked
    assert "(param=email)  [unproven]" in out
    # Finding line marked
    assert "Baseline 401 -> Payload 500  [unproven]" in out


def test_mixed_group_header_unmarked_findings_marked_individually(capsys):
    verified = _base(
        verification_status="verified", verification_reason=None, payload_name="p1"
    )
    unproven = _base(
        verification_status="unproven",
        verification_reason="corroborator_structural",
        payload_name="p2",
    )
    _print_summary(_summary_with_group([verified, unproven]))
    out = capsys.readouterr().out
    # Group header NOT marked (mixed)
    assert "(param=email)  [unproven]" not in out
    # Both findings appear; only the unproven one carries the per-line marker
    lines = [ln for ln in out.splitlines() if ln.strip().startswith("- [")]
    assert len(lines) == 2
    p1_line = next(ln for ln in lines if "[p1]" in ln)
    p2_line = next(ln for ln in lines if "[p2]" in ln)
    assert "[unproven]" not in p1_line
    assert "[unproven]" in p2_line


# --- FN-16 follow-up: severity fallback must surface unproven ---------------


def _summary_ungrouped(findings: list[ScanFinding]) -> ScanSummary:
    """Summary with findings but no groups (the WS recon case).

    Smoke test against a local echo server produced 11 unproven MEDIUM
    findings in 0 groups. The grouped-unproven display (see tests above)
    never runs when findings don't cluster; the severity fallback at
    cli._print_summary (lines 165-172) must show the unproven count itself.
    """
    s = ScanSummary(target="http://x/", params=["q"], method="GET")
    for f in findings:
        if f.verification_status == "unproven":
            s.candidates.append(f)
        else:
            s.findings.append(f)
    s.finding_count = len(s.findings)
    return s


def test_severity_line_shows_unproven_when_findings_not_grouped(capsys):
    findings = [
        _base(
            verification_status="unproven",
            verification_reason="websocket_recon",
            severity="medium",
            category="websocket",
            payload_name=f"p{i}",
        )
        for i in range(3)
    ]
    # Phase 1 dedup collapses findings sharing a fingerprint. ``_base``
    # produces the same fingerprint for all three (same param / category /
    # finding_type / url; only payload_name differs, which is not a
    # fingerprint input per ADR-007). Give each a distinct fingerprint so
    # this test still exercises "3 unproven findings in the MEDIUM
    # severity line", which is what the assertion targets.
    for i, f in enumerate(findings):
        f.fingerprint = f"test-sevline-unproven-{i}"
    _print_summary(_summary_ungrouped(findings))
    out = capsys.readouterr().out
    medium_lines = [ln for ln in out.splitlines() if "MEDIUM" in ln]
    assert medium_lines, f"MEDIUM line missing from severity summary; got {out!r}"
    assert any("unproven: 3" in ln for ln in medium_lines), (
        f"severity line must annotate unproven count; got {medium_lines!r}"
    )


def test_severity_line_mixed_shows_partial_unproven(capsys):
    findings = [
        _base(
            verification_status="unproven",
            verification_reason="websocket_recon",
            severity="medium",
            category="websocket",
            payload_name="p1",
        ),
        _base(
            verification_status="verified",
            verification_reason=None,
            severity="medium",
            category="sqli",
            payload_name="p2",
        ),
    ]
    _print_summary(_summary_ungrouped(findings))
    out = capsys.readouterr().out
    medium_lines = [ln for ln in out.splitlines() if "MEDIUM" in ln]
    assert medium_lines, f"MEDIUM line missing from severity summary; got {out!r}"
    assert any("unproven: 1" in ln for ln in medium_lines), (
        f"mixed severity must show partial unproven count; got {medium_lines!r}"
    )


def test_severity_line_verified_only_has_no_unproven_annotation(capsys):
    findings = [
        _base(
            verification_status="verified",
            verification_reason=None,
            severity="high",
            payload_name="p1",
        ),
    ]
    _print_summary(_summary_ungrouped(findings))
    out = capsys.readouterr().out
    assert "HIGH" in out
    assert "unproven" not in out, (
        f"verified-only scan must not mention unproven; got {out!r}"
    )
