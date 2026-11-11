"""JAN-L02: structured authentication state in scan output.

The full AuthStateManager (reauth workflow, health checks) is a later
work package. This covers the reporting field only: ScanSummary gains
auth_state, populated at scan start and set to a terminal value on the
two-consecutive-401 abort.

scan_ws and scan_graphql are not given auth_state assignments: they are
only invoked from scan(), and their summaries merge into the parent via
_merge_ws_into_scan / _merge_graphql_into_scan, which preserve the
parent's value. A direct caller of scan_ws() sees "unknown", which is
honest because that path has no auth contract.
"""

from unittest.mock import patch

from janissary.cli import _summary_to_dict
from janissary.engine.scanner import ScanSummary, Scanner


def test_scan_summary_defaults_to_unknown():
    """Sub-summaries have no auth context; unknown is the honest default."""
    s = ScanSummary(target="http://x", params=[], method="GET")
    assert s.auth_state == "unknown"


def test_summary_to_dict_includes_auth_state():
    s = ScanSummary(target="http://x", params=[], method="GET")
    s.auth_state = "authenticated"
    d = _summary_to_dict(s)
    assert d["auth_state"] == "authenticated"


def test_scan_sets_unauthenticated_when_not_configured():
    """No credentials supplied: state reflects that, not 'unknown'."""
    scanner = Scanner(target="http://example.test/", params=["x"])
    with patch.object(scanner, "preflight", return_value=(False, "test abort")):
        summary = scanner.scan(quiet=True)
    assert summary.auth_state == "unauthenticated"
    assert summary.aborted is True


def test_scan_sets_authenticated_when_configured():
    scanner = Scanner(target="http://example.test/", params=["x"], auth_configured=True)
    with patch.object(scanner, "preflight", return_value=(False, "test abort")):
        summary = scanner.scan(quiet=True)
    assert summary.auth_state == "authenticated"
    assert summary.aborted is True
