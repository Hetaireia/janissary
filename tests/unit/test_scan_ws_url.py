"""scan_ws must hand learn() a ws:// URL, even when the CLI target is http://.

Regression test for FN-16 part 6: preflight() requires an HTTP target
(uses self._request), while learn() calls websockets.connect() which
requires ws:// or wss://. scan_ws is the seam that has to reconcile them.
"""
from unittest.mock import MagicMock, patch

from janissary.engine.scanner import Scanner


def _scanner(url: str) -> Scanner:
    return Scanner(target=url, params=["q"], method="GET", detect_waf=False)


def _stub_preflight_ok(scanner):
    # preflight() hits the HTTP target; on a local mock URL it would fail.
    # We only care what scan_ws passes to learn(), so short-circuit it.
    scanner.preflight = MagicMock(return_value=(True, ""))


def _stub_learn_empty():
    from janissary.integrations.websocket_learn import LearnedModel
    from janissary.integrations.websocket_learn import MessageSequence
    return LearnedModel(
        wire_format="unknown",
        baseline_sequence=MessageSequence(),
        injectable_fields=[],
        notes=("no injectable fields",),
    )


def _run_scan_ws(scanner, url_seen: list[str]):
    """Call scan_ws with a fake learn() that records the URL it received."""
    fake_model = _stub_learn_empty()

    async def fake_learn(url, payloads=None, timeout=None, **kw):
        url_seen.append(url)
        return fake_model

    with patch("janissary.engine.scanner.learn", new=fake_learn):
        return scanner.scan_ws(payloads=["ping"])


def test_scan_ws_converts_http_target_to_ws_for_learn():
    s = _scanner("http://example.test/graphql")
    _stub_preflight_ok(s)
    seen: list[str] = []
    _run_scan_ws(s, seen)
    assert seen == ["ws://example.test/graphql"], (
        f"learn() was handed {seen!r}; preflight requires http://, "
        f"learn() requires ws://, scan_ws must convert between them"
    )


def test_scan_ws_converts_https_target_to_wss_for_learn():
    s = _scanner("https://example.test/graphql")
    _stub_preflight_ok(s)
    seen: list[str] = []
    _run_scan_ws(s, seen)
    assert seen == ["wss://example.test/graphql"], (
        f"learn() was handed {seen!r}; https target must become wss://"
    )


def test_scan_ws_passes_ws_target_through_unchanged():
    """If the caller already supplied ws://, don't double-convert."""
    s = _scanner("ws://example.test/graphql")
    _stub_preflight_ok(s)
    seen: list[str] = []
    _run_scan_ws(s, seen)
    assert seen == ["ws://example.test/graphql"]
