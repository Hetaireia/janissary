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
from janissary.engine.scanner import Scanner, ScanSummary


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


# ---------------------------------------------------------------------------
# Abort-path tests
#
# The start-of-scan tests above verify the initial state. These cover the
# two-consecutive-401 abort path: `expired` when no rotation is configured,
# `recovery_failed` when rotation was attempted and exhausted. Everything
# except the three network-touching methods is real: the 401 counter,
# ResponseSnapshot.from_response, compute_arming_state, both abort branches.
# ---------------------------------------------------------------------------


def _resp_401():
    import requests

    r = requests.Response()
    r.status_code = 401
    r._content = b"Unauthorized"
    r.headers["content-type"] = "text/plain"
    return r


def _abort_scanner(**kwargs):
    return Scanner(
        target="http://example.test/",
        params=["x"],
        detect_waf=False,
        **kwargs,
    )


def test_two_401s_without_rotator_yields_expired():
    """Two consecutive 401s, no rotation configured: auth_state=expired."""
    from janissary.detection.analyzer import Baseline

    scanner = _abort_scanner(auth_configured=True)
    with (
        patch.object(scanner, "preflight", return_value=(True, "")),
        patch.object(scanner, "collect_baseline", return_value=Baseline()),
        patch.object(scanner, "_paced_request", return_value=_resp_401()),
    ):
        summary = scanner.scan(quiet=True)
    assert summary.aborted is True
    assert summary.auth_state == "expired"
    assert summary.scan_incomplete is True
    assert "auth expired" in (summary.abort_reason or "")


def test_two_401s_with_exhausted_rotator_yields_recovery_failed():
    """Rotation attempted and exhausted: auth_state=recovery_failed."""
    from unittest.mock import MagicMock

    from janissary.detection.analyzer import Baseline

    scanner = _abort_scanner(auth_configured=True)
    rotator = MagicMock()
    rotator.attempted_count = 3
    rotator.total = 3
    scanner._session_rotator = rotator

    with (
        patch.object(scanner, "preflight", return_value=(True, "")),
        patch.object(scanner, "collect_baseline", return_value=Baseline()),
        patch.object(scanner, "_paced_request", return_value=_resp_401()),
    ):
        summary = scanner.scan(quiet=True)
    assert summary.aborted is True
    assert summary.auth_state == "recovery_failed"
    assert "sessions attempted" in (summary.abort_reason or "")


def test_401s_without_auth_configured_do_not_abort():
    """Unauthenticated scans can legitimately receive 401s; no abort.

    The two-consecutive-401 gate is keyed on auth_configured. Without it,
    a 401 is an application response, not a session loss.
    """
    from janissary.detection.analyzer import Baseline

    scanner = _abort_scanner(auth_configured=False)
    with (
        patch.object(scanner, "preflight", return_value=(True, "")),
        patch.object(scanner, "collect_baseline", return_value=Baseline()),
        patch.object(scanner, "_paced_request", return_value=_resp_401()),
    ):
        summary = scanner.scan(quiet=True)
    assert summary.aborted is False
    assert summary.auth_state == "unauthenticated"
