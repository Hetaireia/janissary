"""Tests for --ws / --ws-payloads CLI wiring and _merge_ws_into_scan (FN-16)."""
from argparse import Namespace
from unittest.mock import MagicMock, patch

from janissary.cli import _load_ws_payloads, _merge_ws_into_scan, cmd_scan
from janissary.engine.scanner import ScanFinding, ScanSummary


def _ws_finding(**kw) -> ScanFinding:
    base = dict(
        param="message",
        payload_name="ws_probe",
        payload_value="ping",
        category="websocket",
        severity="info",
        finding_type="websocket_endpoint_discovered",
        detail="WebSocket endpoint discovered",
        url="ws://x/ws",
        method="GET",
        verification_status="unproven",
        verification_reason="websocket_recon",
    )
    base.update(kw)
    f = ScanFinding(**base)
    f._engine_emitted = True
    return f


def _summary(findings=None, **kw):
    s = ScanSummary(
        target=kw.get("target", "http://x/"),
        params=kw.get("params", ["q"]),
        method=kw.get("method", "GET"),
    )
    for f in findings or []:
        s.findings.append(f)
    s.finding_count = len(s.findings)
    s.total_requests = kw.get("total_requests", 10)
    s.aborted = kw.get("aborted", False)
    s.scan_incomplete = kw.get("scan_incomplete", False)
    s.abort_reason = kw.get("abort_reason")
    return s


def _args(**kw):
    base = dict(
        url="http://x/",
        params="q",
        method="GET",
        timeout=10.0,
        baseline_count=10,
        delay=0.0,
        stealth=False,
        no_waf=True,
        inject_in="auto",
        baseline_value="",
        json_template=None,
        quiet=True,
        export=None,
        json=True,
        jsonl=False,
        show_version=False,
        proxy=None,
        graphql=False,
        ws=False,
        ws_payloads=None,
    )
    base.update(kw)
    return Namespace(**base)


def _payload_file(tmp_path, text):
    p = tmp_path / "payloads.txt"
    p.write_text(text, encoding="utf-8")
    return p


# --- _load_ws_payloads -----------------------------------------------------

def test_load_ws_payloads_skips_blanks_and_comments(tmp_path):
    p = _payload_file(tmp_path, "# header\n\nPAY1\n   \n  PAY2  \n# trailing\n")
    assert _load_ws_payloads(p) == ["PAY1", "PAY2"]


# --- _merge_ws_into_scan ---------------------------------------------------

def test_merge_ws_adds_findings_and_sums_requests():
    s = _summary([], total_requests=10)
    ws = _summary([_ws_finding(), _ws_finding(finding_type="websocket_b")], total_requests=7)
    _merge_ws_into_scan(s, ws)
    assert len(s.findings) == 2
    assert s.finding_count == 2
    assert s.total_requests == 17


def test_merge_ws_propagates_scan_incomplete():
    s = _summary([])
    ws = _summary([], scan_incomplete=True, abort_reason="ws incomplete")
    _merge_ws_into_scan(s, ws)
    assert s.scan_incomplete is True
    assert s.abort_reason == "ws incomplete"


def test_merge_ws_propagates_aborted():
    s = _summary([])
    ws = _summary([], aborted=True, abort_reason="ws aborted")
    _merge_ws_into_scan(s, ws)
    assert s.aborted is True
    assert s.abort_reason == "ws aborted"


# --- CLI wiring ------------------------------------------------------------

def test_ws_flags_registered_in_scan_subparser(tmp_path):
    """Argparse must accept --ws and --ws-payloads on scan."""
    import sys
    from janissary.cli import main

    pf = _payload_file(tmp_path, "PAY1\n")
    argv = ["janissary", "scan", "-u", "http://x/",
            "--ws", "--ws-payloads", str(pf), "--json"]
    with patch.object(sys, "argv", argv):
        with patch("janissary.cli.Scanner") as MockScanner:
            inst = MockScanner.return_value
            inst.scan.return_value = _summary([])
            inst.scan_ws.return_value = _summary([])
            try:
                main()
            except SystemExit:
                pass
    assert MockScanner.called, "--ws / --ws-payloads rejected by argparse"
    inst.scan_ws.assert_called_once()


def test_cmd_scan_calls_scan_ws_with_parsed_payloads(tmp_path):
    pf = _payload_file(tmp_path, "# c\n\nPAY1\nPAY2\n")
    args = _args(ws=True, ws_payloads=str(pf))
    with patch("janissary.cli.Scanner") as MockScanner:
        inst = MockScanner.return_value
        inst.scan.return_value = _summary([])
        inst.scan_ws.return_value = _summary([_ws_finding()])
        with patch("janissary.cli.scope_from_args") as mock_scope:
            mock_scope.return_value.require = MagicMock()
            rc = cmd_scan(args)
    inst.scan_ws.assert_called_once_with(payloads=["PAY1", "PAY2"])
    assert rc == 1, "merged WS finding should make cmd_scan exit 1"


def test_cmd_scan_does_not_call_scan_ws_when_flag_absent():
    args = _args()
    with patch("janissary.cli.Scanner") as MockScanner:
        inst = MockScanner.return_value
        inst.scan.return_value = _summary([])
        with patch("janissary.cli.scope_from_args") as mock_scope:
            mock_scope.return_value.require = MagicMock()
            cmd_scan(args)
    inst.scan_ws.assert_not_called()


def test_cmd_scan_ws_without_payloads_is_rejected(capsys):
    args = _args(ws=True, ws_payloads=None)
    with patch("janissary.cli.Scanner") as MockScanner:
        rc = cmd_scan(args)
    assert rc == 64
    assert "--ws requires --ws-payloads" in capsys.readouterr().err
    assert not MockScanner.called, "Scanner must not be constructed"


def test_cmd_scan_ws_missing_payload_file_is_rejected(tmp_path, capsys):
    missing = tmp_path / "nope.txt"
    args = _args(ws=True, ws_payloads=str(missing))
    with patch("janissary.cli.Scanner") as MockScanner:
        rc = cmd_scan(args)
    assert rc == 64
    assert "not found" in capsys.readouterr().err
    assert not MockScanner.called


def test_cmd_scan_ws_empty_payload_file_is_rejected(tmp_path, capsys):
    pf = _payload_file(tmp_path, "# only comments\n\n   \n")
    args = _args(ws=True, ws_payloads=str(pf))
    with patch("janissary.cli.Scanner") as MockScanner:
        rc = cmd_scan(args)
    assert rc == 64
    assert "contained no usable payloads" in capsys.readouterr().err
    assert not MockScanner.called
