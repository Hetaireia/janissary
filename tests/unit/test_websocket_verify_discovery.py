"""Tests for verify() and WebSocketDiscoveryModule (FN-16 part 5)."""
from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from unittest.mock import patch

import websockets

from janissary.engine.scanner import _ENGINE
from janissary.integrations.websocket_discovery import WebSocketDiscoveryModule
from janissary.integrations.websocket_learn import verify
from janissary.protocols.websocket import (
    InjectableField,
    LearnedModel,
    MessageSequence,
    ProbeResult,
    WebSocketMessage,
)
from janissary.verification import VerifiedFinding


@asynccontextmanager
async def _serve(handler):
    server = await websockets.serve(handler, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        yield f"ws://127.0.0.1:{port}"
    finally:
        server.close()
        await server.wait_closed()


def _build_model(baseline_payload: str, response_payload: str) -> LearnedModel:
    """Model with c2s baseline_payload then s2c response_payload, one field."""
    seq = MessageSequence(messages=[
        WebSocketMessage(direction="c2s", payload=baseline_payload),
        WebSocketMessage(direction="s2c", payload=response_payload),
    ])
    field = InjectableField(
        message_index=0, path="a", value_kind="string", original_value="orig",
    )
    return LearnedModel(
        wire_format="json", baseline_sequence=seq, injectable_fields=[field],
    )


def _probe(
    response_frames: tuple[str, ...],
    sent_ok: bool = True,
    category: str = "sqli",
    payload_value: str = "'",
) -> ProbeResult:
    return ProbeResult(
        field_path="a",
        message_index=0,
        payload_name=f"{category}_test",
        payload_value=payload_value,
        category=category,
        original_payload='{"a":"orig"}',
        mutated_payload=json.dumps({"a": payload_value}),
        response_frames=response_frames,
        sent_ok=sent_ok,
    )


# --- verify() unit tests ---


def test_verify_empty_probes():
    model = _build_model('{"a":"orig"}', '{"a":"orig"}')
    assert verify([], model) == []


def test_verify_skips_unsent():
    model = _build_model('{"a":"orig"}', '{"a":"orig"}')
    probe = _probe(('{"a":"x"}',), sent_ok=False)
    assert verify([probe], model) == []


def test_verify_skips_empty_frames():
    model = _build_model('{"a":"orig"}', '{"a":"orig"}')
    probe = _probe((), sent_ok=True)
    assert verify([probe], model) == []


def test_verify_skips_no_baseline():
    seq = MessageSequence(messages=[
        WebSocketMessage(direction="c2s", payload='{"a":"orig"}'),
    ])
    model = LearnedModel(
        wire_format="json", baseline_sequence=seq,
        injectable_fields=[
            InjectableField(
                message_index=0, path="a",
                value_kind="string", original_value="orig",
            ),
        ],
    )
    probe = _probe(('{"a":"x"}',), sent_ok=True)
    assert verify([probe], model) == []


def test_verify_identical_no_candidate():
    model = _build_model('{"a":"orig"}', '{"a":"orig"}')
    probe = _probe(('{"a":"orig"}',), sent_ok=True)
    assert verify([probe], model) == []


def test_verify_different_emits_candidate():
    model = _build_model('{"a":"orig"}', '{"a":"orig"}')
    probe = _probe((json.dumps({"a": "'"}),), sent_ok=True)
    candidates = verify([probe], model, url="ws://test/socket")
    assert len(candidates) == 1


def test_candidate_metadata():
    model = _build_model('{"a":"orig"}', '{"a":"orig"}')
    probe = _probe((json.dumps({"a": "'"}),), sent_ok=True, category="sqli")
    c = verify([probe], model, url="ws://test/socket")[0]
    assert c.finding_type == "websocket_sqli_probe"
    assert c.category == "websocket"
    assert c.severity == "medium"
    assert c.method == "WS"
    assert c.url == "ws://test/socket"
    assert c.param == "a"
    assert c.payload_name == "sqli_test"
    assert c.payload_value == "'"


def test_candidate_routes_through_engine_as_unproven():
    """End-to-end: WebSocket candidate -> engine -> unproven."""
    model = _build_model('{"a":"orig"}', '{"a":"orig"}')
    probe = _probe((json.dumps({"a": "'"}),), sent_ok=True, category="sqli")
    candidate = verify([probe], model, url="ws://test/socket")[0]
    result = _ENGINE.verify(candidate)
    assert isinstance(result, VerifiedFinding)
    assert result.verification_status == "unproven"
    assert result.verification_reason == "websocket_recon"


# --- WebSocketDiscoveryModule tests ---


def test_discovery_empty_model_returns_empty():
    model = LearnedModel(
        wire_format="unknown", baseline_sequence=MessageSequence(),
        injectable_fields=[],
    )
    module = WebSocketDiscoveryModule(url="ws://127.0.0.1:1", model=model)
    candidates = asyncio.run(module.discover())
    assert candidates == []


def test_discovery_end_to_end_echo_produces_candidates():
    """Echo server: mutated payload differs from baseline response."""
    async def handler(ws):
        async for msg in ws:
            await ws.send(msg)

    model = _build_model('{"a":"orig"}', '{"a":"orig"}')
    module = WebSocketDiscoveryModule(url="placeholder", model=model)

    async def run():
        async with _serve(handler) as url:
            module.url = url
            return await module.discover(
                max_probes=2, response_quiet_s=0.1,
            )

    candidates = asyncio.run(run())
    assert len(candidates) == 2
    for c in candidates:
        assert c.finding_type.startswith("websocket_")


def test_discovery_fixed_response_no_candidates():
    """Server always responds identically -> baseline and probe match -> no candidates."""
    async def handler(ws):
        async for _ in ws:
            await ws.send('{"status":"ok"}')

    model = _build_model('{"a":"orig"}', '{"status":"ok"}')
    module = WebSocketDiscoveryModule(url="placeholder", model=model)

    async def run():
        async with _serve(handler) as url:
            module.url = url
            return await module.discover(
                max_probes=2, response_quiet_s=0.1,
            )

    candidates = asyncio.run(run())
    assert candidates == []


def test_discovery_max_probes_passed_to_probe():
    """Mock probe() to capture kwargs; verify() returns []."""
    model = _build_model('{"a":"orig"}', '{"a":"orig"}')
    module = WebSocketDiscoveryModule(url="ws://x", model=model)

    captured = {}

    async def fake_probe(url, model, **kwargs):
        captured.update(kwargs)
        return []

    with patch("janissary.integrations.websocket_discovery.probe", fake_probe):
        asyncio.run(module.discover(max_probes=7, response_quiet_s=0.5))

    assert captured.get("max_probes") == 7
    assert captured.get("response_quiet_s") == 0.5
