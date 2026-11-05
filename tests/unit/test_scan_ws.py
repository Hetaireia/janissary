"""Tests for Scanner.scan_ws() (FN-16 part 6a)."""

from unittest.mock import patch

from janissary.engine.scanner import Scanner
from janissary.integrations.websocket_discovery import WebSocketDiscoveryModule
from janissary.protocols.websocket import (
    InjectableField,
    LearnedModel,
    MessageSequence,
    WebSocketMessage,
)


def _scanner(target="ws://127.0.0.1:1/socket"):
    return Scanner(target=target, params=["p"], method="GET", detect_waf=False)


def _model(injectable: bool = True) -> LearnedModel:
    seq = MessageSequence(
        messages=[
            WebSocketMessage(direction="c2s", payload='{"a":"orig"}'),
            WebSocketMessage(direction="s2c", payload='{"a":"orig"}'),
        ]
    )
    fields = (
        [
            InjectableField(
                message_index=0, path="a", value_kind="string", original_value="orig"
            )
        ]
        if injectable
        else []
    )
    return LearnedModel(
        wire_format="json",
        baseline_sequence=seq,
        injectable_fields=fields,
    )


def _graphql_style_candidate():
    from janissary.verification import CandidateFinding

    return CandidateFinding(
        param="a",
        payload_name="sqli_test",
        payload_value="'",
        category="websocket",
        severity="medium",
        finding_type="websocket_sqli_probe",
        detail="probe on 'a' produced a differing response",
        url="ws://127.0.0.1:1/socket",
        method="WS",
    )


def test_scan_ws_no_payloads_returns_scan_incomplete():
    s = _scanner()
    summary = s.scan_ws(payloads=None)
    assert summary.scan_incomplete is True
    assert summary.abort_reason == "no WS payloads provided"
    assert summary.findings == []


def test_scan_ws_empty_payloads_returns_scan_incomplete():
    s = _scanner()
    summary = s.scan_ws(payloads=[])
    assert summary.scan_incomplete is True
    assert "no WS payloads" in summary.abort_reason


def test_scan_ws_preflight_fail_aborted():
    s = _scanner()
    with patch.object(s, "preflight", return_value=(False, "unreachable")):
        summary = s.scan_ws(payloads=['{"x":1}'])
    assert summary.aborted is True
    assert summary.abort_reason == "unreachable"


def test_scan_ws_learn_connect_failed_scan_incomplete():
    async def fake_learn(*args, **kwargs):
        return LearnedModel(
            wire_format="unknown",
            baseline_sequence=MessageSequence(),
            injectable_fields=[],
            notes=("connect_failed: ConnectionRefusedError: nope",),
        )

    s = _scanner()
    with patch.object(s, "preflight", return_value=(True, "")):
        with patch("janissary.engine.scanner.learn", fake_learn):
            summary = s.scan_ws(payloads=['{"x":1}'])
    assert summary.scan_incomplete is True
    assert "connect failed" in summary.abort_reason.lower()


def test_scan_ws_no_injectable_fields_scan_incomplete():
    async def fake_learn(*args, **kwargs):
        return _model(injectable=False)

    s = _scanner()
    with patch.object(s, "preflight", return_value=(True, "")):
        with patch("janissary.engine.scanner.learn", fake_learn):
            summary = s.scan_ws(payloads=['{"x":1}'])
    assert summary.scan_incomplete is True
    assert "no injectable fields" in summary.abort_reason.lower()


def test_scan_ws_success_findings_verified_and_unproven():
    async def fake_learn(*args, **kwargs):
        return _model(injectable=True)

    async def fake_discover(self, max_probes=50):
        return [_graphql_style_candidate()]

    s = _scanner()
    with patch.object(s, "preflight", return_value=(True, "")):
        with patch("janissary.engine.scanner.learn", fake_learn):
            with patch.object(WebSocketDiscoveryModule, "discover", fake_discover):
                summary = s.scan_ws(payloads=['{"x":1}'])
    assert summary.aborted is False
    assert summary.scan_incomplete is False
    assert len(summary.findings) == 1
    f = summary.findings[0]
    assert f.finding_type == "websocket_sqli_probe"
    assert f.verification_status == "unproven"
    assert f.verification_reason == "websocket_recon"
    assert f.method == "WS"


def test_scan_ws_discover_exception_scan_incomplete():
    async def fake_learn(*args, **kwargs):
        return _model(injectable=True)

    async def fake_discover(self, max_probes=50):
        raise RuntimeError("probe failed")

    s = _scanner()
    with patch.object(s, "preflight", return_value=(True, "")):
        with patch("janissary.engine.scanner.learn", fake_learn):
            with patch.object(WebSocketDiscoveryModule, "discover", fake_discover):
                summary = s.scan_ws(payloads=['{"x":1}'])
    assert summary.scan_incomplete is True
    assert "discover failed" in summary.abort_reason.lower()
