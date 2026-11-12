"""M78a: negative-result messaging distinguishes candidates from clean scans."""

from janissary.cli import _print_summary
from janissary.engine.scanner import ScanFinding, ScanSummary


def _cand(**kw):
    base = {
        "param": "q",
        "payload_name": "heuristic",
        "payload_value": "x",
        "category": "heuristic",
        "severity": "info",
        "finding_type": "heur",
        "detail": "h",
        "url": "http://x/a?q=x",
        "method": "GET",
        "verification_status": "unproven",
        "verification_reason": "heuristic_discovery",
    }
    base.update(kw)
    f = ScanFinding(**base)
    f._engine_emitted = True
    return f


def _vf(**kw):
    base = {
        "param": "q",
        "payload_name": "p",
        "payload_value": "v",
        "category": "sqli",
        "severity": "high",
        "finding_type": "db_error",
        "detail": "SQL error",
        "url": "http://x/a?q=v",
        "method": "GET",
        "verification_status": "verified",
    }
    base.update(kw)
    f = ScanFinding(**base)
    f._engine_emitted = True
    return f


def _summary_with(findings=None, candidates=None, total_requests=5):
    s = ScanSummary(target="http://x/", params=["q"], method="GET")
    s.total_requests = total_requests
    for f in findings or []:
        s.record(f)
    for c in candidates or []:
        s.candidates.append(c)
    return s


def test_zero_verified_zero_candidates_prints_negative_result(capsys):
    _print_summary(_summary_with())
    out = capsys.readouterr().out
    assert "Negative result: no findings" in out


def test_zero_verified_with_candidates_prints_triage_message(capsys):
    _print_summary(_summary_with(candidates=[_cand(), _cand()]))
    out = capsys.readouterr().out
    assert "No verified findings; 2 candidate(s) need triage" in out
    assert "Negative result: no findings" not in out


def test_verified_plus_candidates_prints_both(capsys):
    _print_summary(_summary_with(findings=[_vf()], candidates=[_cand()]))
    out = capsys.readouterr().out
    assert "Findings:        1" in out
    assert "Candidates:      1" in out
    assert "triage" not in out.lower()


def test_candidate_count_does_not_inflate_findings(capsys):
    _print_summary(_summary_with(candidates=[_cand(), _cand(), _cand()]))
    out = capsys.readouterr().out
    assert "Findings:        0" in out
