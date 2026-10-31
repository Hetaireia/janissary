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
    base = dict(
        param="email",
        payload_name="sql_single_quote",
        payload_value="'",
        category="sqli",
        severity="high",
        finding_type="status_change",
        detail="Baseline 401 -> Payload 500",
        url="http://x/",
    )
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
        summary.findings.append(f)
    summary.groups.append(group)
    return summary


def _base(**kw) -> ScanFinding:
    base = dict(
        param="email",
        payload_name="sql_single_quote",
        payload_value="'",
        category="sqli",
        severity="high",
        finding_type="status_change",
        detail="Baseline 401 -> Payload 500",
        url="http://x/",
    )
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
    f = _base(verification_status="unproven", verification_reason="corroborator_structural")
    _print_summary(_summary_with_group([f]))
    out = capsys.readouterr().out
    # Group header marked
    assert "(param=email)  [unproven]" in out
    # Finding line marked
    assert "Baseline 401 -> Payload 500  [unproven]" in out


def test_mixed_group_header_unmarked_findings_marked_individually(capsys):
    verified = _base(verification_status="verified", verification_reason=None, payload_name="p1")
    unproven = _base(verification_status="unproven", verification_reason="corroborator_structural", payload_name="p2")
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