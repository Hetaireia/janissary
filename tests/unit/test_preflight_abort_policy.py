"""Preflight 4xx-vs-5xx abort policy."""

from unittest.mock import MagicMock, patch

from janissary.engine.scanner import Scanner


def _mk_scanner():
    return Scanner(target="http://example.test/", params=["x"])


def _mock_resp(status, body="ok"):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.request = None
    return r


def test_4xx_does_not_abort():
    s = _mk_scanner()
    with patch.object(s, "_request", return_value=_mock_resp(400, '{"error":"x"}')):
        ok, reason = s.preflight()
    assert ok is True, f"400 should pass preflight, got: {reason}"


def test_403_does_not_abort():
    s = _mk_scanner()
    with patch.object(s, "_request", return_value=_mock_resp(403, "Forbidden")):
        ok, _ = s.preflight()
    assert ok is True


def test_404_does_not_abort():
    s = _mk_scanner()
    with patch.object(s, "_request", return_value=_mock_resp(404, "Not Found")):
        ok, _ = s.preflight()
    assert ok is True


def test_500_aborts():
    s = _mk_scanner()
    with patch.object(s, "_request", return_value=_mock_resp(500, "Oops")):
        ok, reason = s.preflight()
    assert ok is False
    assert "500" in reason


def test_503_aborts():
    s = _mk_scanner()
    with patch.object(s, "_request", return_value=_mock_resp(503, "Down")):
        ok, _ = s.preflight()
    assert ok is False


def test_200_empty_body_aborts():
    s = _mk_scanner()
    with patch.object(s, "_request", return_value=_mock_resp(200, "")):
        ok, reason = s.preflight()
    assert ok is False
    assert "empty" in reason.lower()


def test_200_with_body_passes():
    s = _mk_scanner()
    with patch.object(s, "_request", return_value=_mock_resp(200, "<html>x</html>")):
        ok, _ = s.preflight()
    assert ok is True
