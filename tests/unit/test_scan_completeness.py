"""JAN-L10: structured scan completeness in scan output.

The derived scan_complete flag exists so a consumer can distinguish a
complete scan that found nothing from one that terminated early. The
reasons list names only conditions the scanner actually tracks.
"""

from janissary.cli import _scan_completeness, _summary_to_dict
from janissary.engine.scanner import ScanSummary


def _summary(params=("x",), baselines=0):
    s = ScanSummary(target="http://x", params=list(params), method="GET")
    for i in range(baselines):
        s.baselines[f"p{i}"] = {}
    return s


def test_clean_scan_is_complete():
    s = _summary(params=["x"], baselines=1)
    c = _scan_completeness(s)
    assert c["scan_complete"] is True
    assert c["reasons"] == []
    assert c["params_identified"] == 1
    assert c["params_baselined"] == 1


def test_aborted_scan_is_incomplete():
    s = _summary(params=["x"], baselines=1)
    s.aborted = True
    s.abort_reason = "preflight failed"
    c = _scan_completeness(s)
    assert c["scan_complete"] is False
    assert "aborted" in c["reasons"]


def test_scan_incomplete_flag_appears_in_reasons():
    s = _summary(params=["x"], baselines=1)
    s.scan_incomplete = True
    c = _scan_completeness(s)
    assert c["scan_complete"] is False
    assert "scan_incomplete" in c["reasons"]


def test_auth_expiry_appears_in_reasons():
    s = _summary(params=["x"], baselines=1)
    s.auth_state = "expired"
    c = _scan_completeness(s)
    assert c["scan_complete"] is False
    assert "auth_expired" in c["reasons"]


def test_auth_recovery_failed_appears_in_reasons():
    s = _summary(params=["x"], baselines=1)
    s.auth_state = "recovery_failed"
    c = _scan_completeness(s)
    assert c["scan_complete"] is False
    assert "auth_recovery_failed" in c["reasons"]


def test_unbaselined_params_appear_in_reasons():
    s = _summary(params=["a", "b", "c"], baselines=1)
    c = _scan_completeness(s)
    assert c["scan_complete"] is False
    assert "params_unbaselined" in c["reasons"]
    assert c["params_identified"] == 3
    assert c["params_baselined"] == 1


def test_multiple_reasons_accumulate():
    s = _summary(params=["a", "b"], baselines=1)
    s.aborted = True
    s.scan_incomplete = True
    s.auth_state = "expired"
    c = _scan_completeness(s)
    assert c["scan_complete"] is False
    assert set(c["reasons"]) == {
        "aborted",
        "scan_incomplete",
        "auth_expired",
        "params_unbaselined",
    }


def test_completeness_in_summary_dict():
    s = _summary(params=["x"], baselines=1)
    d = _summary_to_dict(s)
    assert "completeness" in d
    assert d["completeness"]["scan_complete"] is True
    assert d["completeness"]["params_identified"] == 1
