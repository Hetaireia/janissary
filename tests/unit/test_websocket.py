"""Unit tests for the WebSocket harness.

Each test spins up a short-lived ``websockets.serve`` instance on
localhost and points ``scan`` at it. No mocks of the protocol layer.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import websockets

from janissary.integrations import websocket as w

# ---------------------------------------------------------------------------
# Test server
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _serve(handler):
    """Start a WebSocket server on an ephemeral localhost port."""
    server = await websockets.serve(handler, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        yield f"ws://127.0.0.1:{port}"
    finally:
        server.close()
        await server.wait_closed()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_is_plaintext_true_for_public_ws():
    assert w.is_plaintext("ws://example.com/socket") is True


def test_is_plaintext_false_for_loopback():
    assert w.is_plaintext("ws://127.0.0.1:9001") is False
    assert w.is_plaintext("ws://localhost:9001") is False


def test_is_plaintext_false_for_wss():
    assert w.is_plaintext("wss://example.com/socket") is False


def test_profile_to_dict_roundtrip():
    p = w.WebSocketProfile(url="ws://x/", reachable=True, scheme="ws")
    d = p.to_dict()
    assert d["url"] == "ws://x/"
    assert d["scheme"] == "ws"
    assert d["findings"] == []


def test_profile_to_json():
    p = w.WebSocketProfile(url="ws://x/", reachable=True)
    s = w.profile_to_json(p)
    assert '"url": "ws://x/"' in s


# ---------------------------------------------------------------------------
# Handshake / baseline
# ---------------------------------------------------------------------------


def test_unreachable_server_reports_note():
    async def run():
        # Nothing listening on this port.
        return await w.scan("ws://127.0.0.1:1/socket", timeout=1.0)

    profile = asyncio.run(run())
    assert profile.reachable is False
    assert any("connect failed" in n for n in profile.notes)


def test_handshake_completes():
    async def handler(ws):
        await ws.wait_closed()

    async def run():
        async with _serve(handler) as url:
            return await w.scan(url, timeout=2.0, evil_origin=None)

    profile = asyncio.run(run())
    assert profile.reachable is True
    assert profile.scheme == "ws"


# ---------------------------------------------------------------------------
# Echo detection
# ---------------------------------------------------------------------------


def test_echo_payload_flagged():
    async def handler(ws):
        async for msg in ws:
            await ws.send(msg)

    async def run():
        async with _serve(handler) as url:
            return await w.scan(
                url,
                timeout=2.0,
                echo_payload="<script>alert(1)</script>",
                evil_origin=None,
            )

    profile = asyncio.run(run())
    cats = [f.category for f in profile.findings]
    assert "echo" in cats
    echo = next(f for f in profile.findings if f.category == "echo")
    assert echo.severity == "medium"
    assert "script" in echo.detail


def test_silent_server_no_echo_finding():
    async def handler(ws):
        # Read but never reply.
        async for _ in ws:
            pass

    async def run():
        async with _serve(handler) as url:
            return await w.scan(url, timeout=1.0, evil_origin=None)

    profile = asyncio.run(run())
    cats = [f.category for f in profile.findings]
    assert "echo" not in cats
    assert any("no reply" in n for n in profile.notes)


# ---------------------------------------------------------------------------
# Origin check
# ---------------------------------------------------------------------------


def test_origin_not_checked_is_flagged():
    async def handler(ws):
        async for msg in ws:
            await ws.send(msg)

    async def run():
        async with _serve(handler) as url:
            return await w.scan(url, timeout=2.0, evil_origin="http://evil.example.com")

    profile = asyncio.run(run())
    cats = [f.category for f in profile.findings]
    assert "missing-origin-check" in cats
    finding = next(f for f in profile.findings if f.category == "missing-origin-check")
    assert finding.severity == "high"


def test_origin_enforced_no_finding():
    """Model real CSWSH protection: reject at handshake via process_request."""
    from http import HTTPStatus

    async def handler(ws):
        async for msg in ws:
            await ws.send(msg)

    async def process_request(connection, request):
        origin = request.headers.get("Origin", "")
        if "evil" in origin:
            return connection.respond(HTTPStatus.FORBIDDEN, "Forbidden\n")
        return None

    async def run():
        server = await websockets.serve(
            handler, "127.0.0.1", 0, process_request=process_request
        )
        try:
            port = server.sockets[0].getsockname()[1]
            url = f"ws://127.0.0.1:{port}"
            return await w.scan(url, timeout=2.0, evil_origin="http://evil.example.com")
        finally:
            server.close()
            await server.wait_closed()

    profile = asyncio.run(run())
    cats = [f.category for f in profile.findings]
    assert "missing-origin-check" not in cats
    assert any("origin" in n.lower() for n in profile.notes)


# ---------------------------------------------------------------------------
# plaintext finding
# ---------------------------------------------------------------------------


def test_plaintext_finding_only_for_public_ws():
    # We cannot actually connect to example.com in a unit test, so
    # just verify the finding decision path via is_plaintext.
    assert w.is_plaintext("ws://example.com") is True
    assert w.is_plaintext("ws://127.0.0.1") is False


# ---------------------------------------------------------------------------
# Sync wrapper
# ---------------------------------------------------------------------------


def test_scan_sync_runs_in_sync_context():
    """scan_sync must work from a thread that has no running event loop.

    We keep the server alive in a background thread and call scan_sync
    from the main thread.
    """
    import threading

    async def handler(ws):
        async for msg in ws:
            await ws.send(msg)

    url_box: dict = {}
    ready = threading.Event()
    stop = threading.Event()

    def server_thread():
        async def run():
            async with _serve(handler) as url:
                url_box["url"] = url
                ready.set()
                while not stop.is_set():
                    await asyncio.sleep(0.05)

        asyncio.run(run())

    t = threading.Thread(target=server_thread, daemon=True)
    t.start()
    try:
        assert ready.wait(timeout=5), "server never started"
        url = url_box["url"]
        profile = w.scan_sync(url, timeout=2.0, evil_origin=None)
        assert profile.reachable is True
    finally:
        stop.set()
        t.join(timeout=5)
