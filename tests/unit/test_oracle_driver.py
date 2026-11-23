"""Tests for the tier-A oracle driver (ADR-035).

The driver is proved neutral before any site migrates: on one fixture it has
to produce a byte-identical ScanFinding to a frozen copy of the inline
construction-and-routing body it replaces (_legacy_securecookie). The
remaining tests cover the behaviours ADR-035 gates: verified hits are
recorded, the quiet line is suppressed when quiet is set, a supplied
seen-guard suppresses every hit after the first, and each oracle argument
shape feeds the oracle the arguments it actually declares.

Serialisers are stubbed so parity is about construction and routing, and the
stub call order is asserted too -- that is what proves the driver hands the
response, not the snapshot, to the second positional argument.
"""

from dataclasses import fields
from types import SimpleNamespace
from typing import ClassVar

from janissary.engine import scanner
from janissary.engine.scanner import (
    _emit_oracle_findings,
    _OracleSeenGuard,
    _to_scan_finding,
)
from janissary.verification import CandidateFinding, VerifiedFinding

MARKER = "tb-9f2c41d7"
COOKIE = f"sid={MARKER}; Path=/"
TARGET = "http://t/a"

_VERIFIED_FIELDS = {f.name for f in fields(VerifiedFinding)}


class _Prepared:
    url = f"{TARGET}?uid={MARKER}"
    method = "POST"
    headers: ClassVar[dict] = {"Host": "t"}
    body = f"uid={MARKER}"


class _Resp:
    status_code = 200
    text = "ok"
    reason = "OK"
    headers: ClassVar[dict] = {"content-type": "text/html"}
    content = b"ok"
    request = _Prepared()


class _Engine:
    """Promote every candidate to a verified VerifiedFinding.

    CandidateFinding carries discovery_reason, which VerifiedFinding does not,
    so only the shared field names are forwarded.
    """

    def verify(self, candidate):
        promoted = {
            f.name: getattr(candidate, f.name)
            for f in fields(candidate)
            if f.name in _VERIFIED_FIELDS
        }
        return VerifiedFinding(**promoted, verification_status="verified")


class _Recorder:
    def __init__(self):
        self.recorded = []

    def record(self, finding):
        self.recorded.append(finding)
        return True


_HIT = {
    "severity": "medium",
    "type": "securecookie_flag_oracle",
    "detail": "Cookie echoed the injected marker without the Secure attribute: "
    + COOKIE,
    "evidence": COOKIE,
}


def _oracle(baseline, response, marker):
    assert marker == MARKER
    assert response.request.url.endswith(MARKER)
    return [dict(_HIT)]


def _wire(monkeypatch):
    says = []
    serialised = []
    monkeypatch.setattr(scanner, "_ENGINE", _Engine())
    monkeypatch.setattr(scanner, "_say", lambda *a, **k: says.append(a))
    monkeypatch.setattr(
        scanner, "serialize_request", lambda q: serialised.append(("req", q)) or "REQ"
    )
    monkeypatch.setattr(
        scanner,
        "serialize_response",
        lambda q: serialised.append(("resp", q)) or "RESP",
    )
    return says, serialised


def _args(record, over=None):
    base = {
        "param": "uid",
        "payload_value": MARKER,
        "response": _Resp(),
        "snapshot": SimpleNamespace(elapsed=0.1, content_type="text/html"),
        "baseline": SimpleNamespace(snapshots=[]),
        "shape": scanner._SHAPE_RESPONSE_MARKER,
        "payload_name": "securecookie_flag_oracle",
        "category": "securecookie",
        "finding_type": "securecookie_flag_oracle",
        "severity": "medium",
        "target": TARGET,
        "method": "POST",
        "summary": record,
        "quiet": False,
    }
    base.update(over or {})
    return base


def _legacy_securecookie(param, payload_value, response, snapshot, quiet, summary):
    """Frozen copy of the pre-migration securecookie site body."""
    sc_findings = _oracle(None, response, payload_value)
    for f in sc_findings:
        sc_req = getattr(response, "request", None)
        candidate = CandidateFinding(
            param=param,
            payload_name="securecookie_flag_oracle",
            payload_value=payload_value,
            category="securecookie",
            severity=f.get("severity", "medium"),
            finding_type=f.get("type", "securecookie_flag_oracle"),
            detail=f.get("detail", ""),
            response_status=response.status_code,
            response_length=len(response.text or ""),
            response_time=snapshot.elapsed,
            response_content_type=snapshot.content_type,
            url=getattr(sc_req, "url", None) or TARGET,
            method="POST",
            raw_request=scanner.serialize_request(sc_req),
            raw_response=scanner.serialize_response(response),
        )
        result = scanner._ENGINE.verify(candidate)
        if not isinstance(result, VerifiedFinding):
            continue
        sc_finding = _to_scan_finding(result)
        summary.record(sc_finding)
        if not quiet:
            scanner._say(
                f"  [{param}] {sc_finding.payload_name} -> "
                f"{sc_finding.severity.upper()}: "
                f"{sc_finding.finding_type} "
                f"| {sc_finding.detail[:80]}"
            )


def test_driver_matches_legacy_securecookie_field_for_field(monkeypatch):
    says, serialised = _wire(monkeypatch)
    resp = _Resp()
    snap = SimpleNamespace(elapsed=0.1, content_type="text/html")
    base = SimpleNamespace(snapshots=[])

    legacy = _Recorder()
    _legacy_securecookie("uid", MARKER, resp, snap, False, legacy)
    legacy_says = list(says)
    legacy_ser = list(serialised)
    says.clear()
    serialised.clear()

    record = _Recorder()
    _emit_oracle_findings(
        _oracle, **_args(record, {"response": resp, "snapshot": snap, "baseline": base})
    )

    assert len(legacy.recorded) == 1
    assert record.recorded == legacy.recorded
    assert record.recorded[0].fingerprint == legacy.recorded[0].fingerprint
    assert says == legacy_says
    assert serialised == legacy_ser
    assert serialised[1] == ("resp", resp)
    assert isinstance(record.recorded[0], scanner.ScanFinding)
    assert record.recorded[0].raw_response == "RESP"
    assert record.recorded[0].response_time == 0.1


def test_quiet_suppresses_the_line_but_still_records(monkeypatch):
    says, _ = _wire(monkeypatch)
    record = _Recorder()
    _emit_oracle_findings(_oracle, **_args(record, {"quiet": True}))
    assert len(record.recorded) == 1
    assert says == []


def test_seen_guard_blocks_every_call_after_the_first(monkeypatch):
    calls = []

    def counted(baseline, response, marker):
        calls.append(marker)
        return [dict(_HIT)]

    _wire(monkeypatch)
    guard = _OracleSeenGuard()
    record = _Recorder()
    for _ in range(2):
        _emit_oracle_findings(counted, **_args(record, {"seen_guard": guard}))
    assert guard.fired is True
    assert len(calls) == 1
    assert len(record.recorded) == 1


def test_seen_guard_trips_even_when_nothing_verifies(monkeypatch):
    class _Reject:
        def verify(self, candidate):
            return SimpleNamespace(verification_status="unproven")

    _wire(monkeypatch)
    monkeypatch.setattr(scanner, "_ENGINE", _Reject())
    guard = _OracleSeenGuard()
    record = _Recorder()
    _emit_oracle_findings(_oracle, **_args(record, {"seen_guard": guard}))
    assert guard.fired is True
    assert record.recorded == []


def test_shape_feeds_each_oracle_its_own_arguments(monkeypatch):
    seen = []

    def snapshot_only(baseline, snapshot):
        seen.append(("snapshot", snapshot.content_type))
        return []

    def snapshot_marker(baseline, snapshot, marker):
        seen.append(("snapshot+marker", marker))
        return []

    _wire(monkeypatch)
    record = _Recorder()
    snap = SimpleNamespace(elapsed=0.1, content_type="text/html")
    _emit_oracle_findings(
        snapshot_only,
        **_args(record, {"snapshot": snap, "shape": scanner._SHAPE_SNAPSHOT_ONLY}),
    )
    _emit_oracle_findings(
        snapshot_marker,
        **_args(record, {"snapshot": snap, "shape": scanner._SHAPE_SNAPSHOT_MARKER}),
    )
    assert seen == [("snapshot", "text/html"), ("snapshot+marker", MARKER)]
    assert record.recorded == []
