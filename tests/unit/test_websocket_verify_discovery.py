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


# --- FN-16 follow-up: detail string delta classification -------------------

def test_classify_delta_echoed_payload():
    """Payload value appearing in probe_norm but not baseline_norm -> echoed_payload."""
    from janissary.integrations.websocket_learn import _classify_delta

    p = _probe(response_frames=(), payload_value="ECHO_MARKER")
    kind = _classify_delta(
        p, baseline_norm="orig", probe_norm="orig ECHO_MARKER",
    )
    assert kind == "echoed_payload", (
        f"payload present only in probe_norm must classify as echoed_payload; "
        f"got {kind!r}"
    )


def test_classify_delta_length_delta():
    """Same frame count, different body length -> length_delta."""
    from janissary.integrations.websocket_learn import _classify_delta

    p = _probe(response_frames=(), payload_value="NOT_PRESENT_IN_EITHER")
    kind = _classify_delta(
        p, baseline_norm="ok", probe_norm="error internal",
        baseline_frame_count=1, probe_frame_count=1,
    )
    assert kind == "length_delta", (
        f"same-count length difference must classify as length_delta; got {kind!r}"
    )


def test_verify_detail_carries_delta_classification():
    """End-to-end: verify() must put a delta tag in detail for every candidate."""
    model = _build_model('{"a":"orig"}', '{"a":"orig"}')
    probe = _probe(
        response_frames=('{"a":"different"}',),
        payload_value="some_payload",
    )
    candidates = verify([probe], model, url="ws://x")
    assert len(candidates) == 1, (
        f"verify() should emit a candidate for a differing response; "
        f"got {len(candidates)}"
    )
    detail = candidates[0].detail
    assert "delta" in detail, (
        f"candidate detail must include delta classification; got {detail!r}"
    )


def test_classify_delta_frame_count_delta():
    """Different number of s2c frames -> frame_count_delta."""
    from janissary.integrations.websocket_learn import _classify_delta

    p = _probe(response_frames=(), payload_value="NOT_PRESENT_IN_EITHER")
    kind = _classify_delta(
        p, baseline_norm="ab", probe_norm="cd",
        baseline_frame_count=1, probe_frame_count=2,
    )
    assert kind == "frame_count_delta", (
        f"differing frame counts must classify as frame_count_delta; got {kind!r}"
    )


def test_classify_delta_content_delta():
    """Same frame count and length, different content -> content_delta."""
    from janissary.integrations.websocket_learn import _classify_delta

    p = _probe(response_frames=(), payload_value="NOT_PRESENT_IN_EITHER")
    kind = _classify_delta(
        p, baseline_norm="abc", probe_norm="xyz",
        baseline_frame_count=1, probe_frame_count=1,
    )
    assert kind == "content_delta", (
        f"same-length different-content must classify as content_delta; got {kind!r}"
    )


def test_classify_delta_precedence_echo_over_frame_count():
    """echoed_payload must win precedence even when frame counts also differ."""
    from janissary.integrations.websocket_learn import _classify_delta

    p = _probe(response_frames=(), payload_value="ECHO")
    kind = _classify_delta(
        p, baseline_norm="a", probe_norm="aECHO",
        baseline_frame_count=1, probe_frame_count=2,
    )
    assert kind == "echoed_payload", (
        f"echo precedence must override frame_count_delta; got {kind!r}"
    )
