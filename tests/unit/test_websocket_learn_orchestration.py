"""Tests for WebSocket learn() orchestration (Phase 2.2 + FN-16 part 3).

Uses the same in-process websockets.serve pattern as test_websocket.py.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import websockets

from janissary.integrations.websocket_learn import learn


@asynccontextmanager
async def _serve(handler):
    server = await websockets.serve(handler, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        yield f"ws://127.0.0.1:{port}"
    finally:
        server.close()
        await server.wait_closed()


def _fast_kwargs():
    return {"timeout": 1.5, "passive_window_s": 0.1, "response_quiet_s": 0.1}


def test_learn_empty_payloads_returns_honest_empty_model():
    model = asyncio.run(learn("ws://127.0.0.1:1", payloads=[]))
    assert model.wire_format == "unknown"
    assert model.injectable_fields == []
    assert model.baseline_sequence.messages == []
    assert "no_probe_payloads_provided" in model.notes


def test_learn_connect_failure_returns_honest_model():
    model = asyncio.run(
        learn("ws://127.0.0.1:1", payloads=['{"x":1}'], **_fast_kwargs())
    )
    assert model.wire_format == "unknown"
    assert model.injectable_fields == []
    assert any("connect_failed" in n for n in model.notes)


def test_learn_echo_server_discovers_injectable_field():
    async def handler(ws):
        async for msg in ws:
            await ws.send(msg)

    async def run():
        async with _serve(handler) as url:
            return await learn(url, payloads=['{"name":"alice"}'], **_fast_kwargs())

    model = asyncio.run(run())
    assert model.wire_format == "json"
    assert len(model.injectable_fields) == 1
    f = model.injectable_fields[0]
    assert f.path == "name"
    assert f.value_kind == "string"
    assert f.original_value == "alice"
    assert f.message_index == 0


def test_learn_captures_both_directions():
    async def handler(ws):
        async for msg in ws:
            await ws.send(msg)

    async def run():
        async with _serve(handler) as url:
            return await learn(url, payloads=['{"a":1}'], **_fast_kwargs())

    model = asyncio.run(run())
    directions = [m.direction for m in model.baseline_sequence.messages]
    assert "c2s" in directions
    assert "s2c" in directions


def test_learn_non_json_payload_no_injectables_with_note():
    async def handler(ws):
        async for msg in ws:
            await ws.send(msg)

    async def run():
        async with _serve(handler) as url:
            return await learn(url, payloads=["plain text"], **_fast_kwargs())

    model = asyncio.run(run())
    assert model.injectable_fields == []
    assert "no_injectable_fields_found" in model.notes
    assert model.wire_format == "text"


def test_learn_passive_window_captures_server_greeting():
    async def handler(ws):
        await ws.send('{"type":"greeting"}')
        async for msg in ws:
            await ws.send(msg)

    async def run():
        async with _serve(handler) as url:
            return await learn(
                url,
                payloads=['{"x":1}'],
                timeout=1.5,
                passive_window_s=0.2,
                response_quiet_s=0.1,
            )

    model = asyncio.run(run())
    assert len(model.baseline_sequence.messages) >= 3
    assert model.baseline_sequence.messages[0].direction == "s2c"
    assert model.baseline_sequence.messages[0].payload == '{"type":"greeting"}'
    c2s_indices = [
        i
        for i, m in enumerate(model.baseline_sequence.messages)
        if m.direction == "c2s"
    ]
    assert c2s_indices == [1]
    assert model.baseline_sequence.messages[1].payload == '{"x":1}'


def test_learn_multiple_payloads_multiple_c2s_frames():
    async def handler(ws):
        async for msg in ws:
            await ws.send(msg)

    async def run():
        async with _serve(handler) as url:
            return await learn(
                url,
                payloads=['{"a":1}', '{"b":2}'],
                **_fast_kwargs(),
            )

    model = asyncio.run(run())
    c2s_payloads = [
        m.payload for m in model.baseline_sequence.messages if m.direction == "c2s"
    ]
    assert c2s_payloads == ['{"a":1}', '{"b":2}']
    paths = [f.path for f in model.injectable_fields]
    assert "a" in paths
    assert "b" in paths


def test_learn_silent_server_records_c2s_only():
    async def handler(ws):
        async for _ in ws:
            pass

    async def run():
        async with _serve(handler) as url:
            return await learn(
                url,
                payloads=['{"x":1}'],
                timeout=0.5,
                passive_window_s=0.1,
                response_quiet_s=0.1,
            )

    model = asyncio.run(run())
    directions = [m.direction for m in model.baseline_sequence.messages]
    assert directions == ["c2s"]
    assert len(model.injectable_fields) == 1
    assert model.injectable_fields[0].path == "x"
