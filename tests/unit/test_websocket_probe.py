"""Tests for WebSocket probe() orchestration (Phase 2.2 + FN-16 part 4)."""
from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager

import websockets

from janissary.integrations.websocket_learn import (
    WS_PROBE_PAYLOADS,
    probe,
)
from janissary.protocols.websocket import (
    InjectableField,
    LearnedModel,
    MessageSequence,
    WebSocketMessage,
)


@asynccontextmanager
async def _serve(handler):
    server = await websockets.serve(handler, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        yield f"ws://127.0.0.1:{port}"
    finally:
        server.close()
        await server.wait_closed()


def _fast():
    return dict(timeout=1.5, response_quiet_s=0.1)


def _model_with_field(
    payload: str,
    path: str,
    message_index: int = 0,
    extra_messages=None,
) -> LearnedModel:
    messages = list(extra_messages or [])
    # Pad so message_index points at our payload
    while len(messages) < message_index:
        messages.append(WebSocketMessage(direction="s2c", payload="filler"))
    messages.insert(message_index, WebSocketMessage(direction="c2s", payload=payload))
    seq = MessageSequence(messages=messages)
    field = InjectableField(
        message_index=message_index,
        path=path,
        value_kind="string",
        original_value="orig",
    )
    return LearnedModel(
        wire_format="json",
        baseline_sequence=seq,
        injectable_fields=[field],
    )


def test_probe_empty_model_returns_empty():
    model = LearnedModel(
        wire_format="unknown",
        baseline_sequence=MessageSequence(),
        injectable_fields=[],
    )
    results = asyncio.run(probe("ws://127.0.0.1:1", model, **_fast()))
    assert results == []


def test_probe_empty_payloads_returns_empty():
    model = _model_with_field('{"name":"x"}', "name")
    results = asyncio.run(probe("ws://127.0.0.1:1", model, payloads=[], **_fast()))
    assert results == []


def test_probe_max_probes_cap():
    async def handler(ws):
        async for msg in ws:
            await ws.send(msg)

    # Model with one field, 11 default payloads, cap at 5
    model = _model_with_field('{"a":"orig"}', "a")

    async def run():
        async with _serve(handler) as url:
            return await probe(url, model, max_probes=5, **_fast())

    results = asyncio.run(run())
    assert len(results) == 5


def test_probe_happy_path_echo():
    async def handler(ws):
        async for msg in ws:
            await ws.send(msg)

    model = _model_with_field('{"name":"orig"}', "name")
    payloads = [("sqli_quote", "'", "sqli")]

    async def run():
        async with _serve(handler) as url:
            return await probe(url, model, payloads=payloads, **_fast())

    results = asyncio.run(run())
    assert len(results) == 1
    r = results[0]
    assert r.field_path == "name"
    assert r.message_index == 0
    assert r.payload_name == "sqli_quote"
    assert r.payload_value == "'"
    assert r.category == "sqli"
    assert r.sent_ok is True
    assert r.error_note is None
    # Mutated payload should differ from original and contain the injection
    assert json.loads(r.mutated_payload)["name"] == "'"
    assert "'" in r.mutated_payload
    # Echo server should have replied with our mutated message
    assert len(r.response_frames) >= 1
    assert any("'" in frame for frame in r.response_frames)


def test_probe_replays_handshake_before_mutation():
    """Multi-message model: a required AUTH frame precedes the mutated
    frame. Without replay, the server refuses the connection and no
    response comes back."""
    seen: list[str] = []

    async def handler(ws):
        try:
            first = await ws.recv()
        except Exception:
            return
        if first != "AUTH":
            await ws.close()
            return
        async for msg in ws:
            seen.append(msg)
            await ws.send(msg)

    # Build a 2-message model: c2s AUTH at 0, c2s JSON at 1.
    seq = MessageSequence(messages=[
        WebSocketMessage(direction="c2s", payload="AUTH"),
        WebSocketMessage(direction="c2s", payload='{"a":"orig"}'),
    ])
    field = InjectableField(
        message_index=1, path="a", value_kind="string", original_value="orig",
    )
    model = LearnedModel(
        wire_format="json", baseline_sequence=seq, injectable_fields=[field],
    )
    payloads = [("sqli_quote", "'", "sqli")]

    async def run():
        async with _serve(handler) as url:
            return await probe(url, model, payloads=payloads, **_fast())

    results = asyncio.run(run())
    assert len(results) == 1
    r = results[0]
    assert r.sent_ok is True
    # If the AUTH replay worked, the server accepted the connection and
    # echoed our mutated message. If replay failed, response_frames is
    # empty and `seen` is empty (server closed before seeing AUTH).
    assert len(r.response_frames) >= 1, (
        f"no response frames — replay may have failed; server saw {seen}"
    )
    assert len(seen) >= 1


def test_probe_silent_server_records_empty_frames():
    async def handler(ws):
        async for _ in ws:
            pass

    model = _model_with_field('{"a":"orig"}', "a")
    payloads = [("sqli_quote", "'", "sqli")]

    async def run():
        async with _serve(handler) as url:
            return await probe(
                url, model, payloads=payloads,
                timeout=0.5, response_quiet_s=0.1,
            )

    results = asyncio.run(run())
    assert len(results) == 1
    r = results[0]
    assert r.sent_ok is True
    assert r.response_frames == ()


def test_probe_invalid_field_index_skipped():
    """Defensive: field pointing beyond the sequence should be skipped
    without crashing and without emitting a result."""
    model = LearnedModel(
        wire_format="json",
        baseline_sequence=MessageSequence(messages=[]),
        injectable_fields=[
            InjectableField(
                message_index=99, path="a",
                value_kind="string", original_value="x",
            ),
        ],
    )
    results = asyncio.run(probe("ws://127.0.0.1:1", model, **_fast()))
    assert results == []


def test_probe_field_on_s2c_message_skipped():
    """Defensive: field pointing at an s2c message must be skipped
    (we cannot mutate server-authored frames)."""
    seq = MessageSequence(messages=[
        WebSocketMessage(direction="s2c", payload='{"a":"x"}'),
    ])
    model = LearnedModel(
        wire_format="json", baseline_sequence=seq,
        injectable_fields=[
            InjectableField(
                message_index=0, path="a",
                value_kind="string", original_value="x",
            ),
        ],
    )
    results = asyncio.run(probe("ws://127.0.0.1:1", model, **_fast()))
    assert results == []


def test_probe_mutation_failure_recorded():
    """Hand-constructed bad path: set_field_value raises; result carries
    sent_ok=False and a mutation_failed note (one per payload attempted)."""
    async def handler(ws):
        async for msg in ws:
            await ws.send(msg)

    model = _model_with_field('{"a":"orig"}', "does_not_exist")
    payloads = [("sqli_quote", "'", "sqli"), ("xss_script", "<script>", "xss")]

    async def run():
        async with _serve(handler) as url:
            return await probe(url, model, payloads=payloads, **_fast())

    results = asyncio.run(run())
    assert len(results) == 2
    for r in results:
        assert r.sent_ok is False
        assert r.error_note is not None
        assert "mutation_failed" in r.error_note


def test_probe_connect_failure_recorded():
    """Dead port: connect fails; every payload gets a connect_failed result."""
    model = _model_with_field('{"a":"orig"}', "a")
    payloads = [("sqli_quote", "'", "sqli")]

    async def run():
        return await probe(
            "ws://127.0.0.1:1", model, payloads=payloads, timeout=0.5,
            response_quiet_s=0.1,
        )

    results = asyncio.run(run())
    assert len(results) == 1
    r = results[0]
    assert r.sent_ok is False
    assert r.error_note is not None
    assert "connect_failed" in r.error_note


def test_probe_multiple_payloads_multiple_results():
    async def handler(ws):
        async for msg in ws:
            await ws.send(msg)

    model = _model_with_field('{"a":"orig"}', "a")
    payloads = [
        ("sqli_quote", "'", "sqli"),
        ("xss_script", "<script>alert(1)</script>", "xss"),
    ]

    async def run():
        async with _serve(handler) as url:
            return await probe(url, model, payloads=payloads, **_fast())

    results = asyncio.run(run())
    assert len(results) == 2
    names = [r.payload_name for r in results]
    assert "sqli_quote" in names
    assert "xss_script" in names
    for r in results:
        assert r.sent_ok is True
        assert len(r.response_frames) >= 1


def test_probe_result_to_dict_roundtrip():
    async def handler(ws):
        async for msg in ws:
            await ws.send(msg)

    model = _model_with_field('{"a":"orig"}', "a")
    payloads = [("sqli_quote", "'", "sqli")]

    async def run():
        async with _serve(handler) as url:
            return await probe(url, model, payloads=payloads, **_fast())

    r = asyncio.run(run())[0]
    d = r.to_dict()
    assert d["field_path"] == "a"
    assert d["message_index"] == 0
    assert d["payload_name"] == "sqli_quote"
    assert d["payload_value"] == "'"
    assert d["category"] == "sqli"
    assert d["sent_ok"] is True
    assert isinstance(d["response_frames"], list)
    assert d["error_note"] is None
