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
    response_time: float | None = None,
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
        response_time=response_time,
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

# --- FN-21 gap 2: probe-path timing capture ---


def test_probe_result_has_response_time_field():
    """ProbeResult must expose response_time, default None.

    None distinguishes "no timing captured" from "instant response" (0.0).
    """
    from janissary.protocols.websocket import ProbeResult

    p = ProbeResult(
        field_path="a", message_index=0, payload_name="x",
        payload_value="'", category="sqli",
        original_payload="o", mutated_payload="m",
        response_frames=(), sent_ok=True,
    )
    assert hasattr(p, "response_time"), (
        "ProbeResult must expose response_time (FN-21 gap 2)"
    )
    assert p.response_time is None, (
        f"response_time default must be None, got {p.response_time!r}"
    )

    p2 = ProbeResult(
        field_path="a", message_index=0, payload_name="x",
        payload_value="'", category="sqli",
        original_payload="o", mutated_payload="m",
        response_frames=(), sent_ok=True,
        response_time=0.42,
    )
    assert p2.response_time == 0.42


def test_probe_result_to_dict_includes_response_time():
    """to_dict() serializes response_time so it survives to JSON."""
    from janissary.protocols.websocket import ProbeResult

    p = ProbeResult(
        field_path="a", message_index=0, payload_name="x",
        payload_value="'", category="sqli",
        original_payload="o", mutated_payload="m",
        response_frames=(), sent_ok=True,
        response_time=0.42,
    )
    d = p.to_dict()
    assert "response_time" in d, (
        f"to_dict() must include response_time; got keys {list(d.keys())}"
    )
    assert d["response_time"] == 0.42


def test_collect_s2c_with_timing_returns_first_frame_time():
    """_collect_s2c_with_timing reports elapsed seconds to first frame."""
    import asyncio

    class FakeWs:
        def __init__(self, frames, delays):
            self._frames = list(frames)
            self._delays = list(delays)
        async def recv(self):
            if self._delays:
                await asyncio.sleep(self._delays.pop(0))
            if not self._frames:
                await asyncio.sleep(3600)
            return self._frames.pop(0)

    from janissary.integrations.websocket_learn import _collect_s2c_with_timing

    async def run():
        ws = FakeWs(["f1", "f2"], [0.05, 0.0])
        return await _collect_s2c_with_timing(
            ws, quiet_s=0.1, total_budget_s=0.5
        )

    frames, first_s = asyncio.run(run())
    assert frames == ["f1", "f2"], f"frames: {frames!r}"
    assert first_s is not None, "first_s must be a float when a frame arrived"
    assert 0.04 < first_s < 0.15, (
        f"first_s ~= 0.05s expected (tolerance 0.04-0.15), got {first_s!r}"
    )


def test_collect_s2c_with_timing_returns_none_on_timeout():
    """_collect_s2c_with_timing returns None for first_s when no frame arrived."""
    import asyncio

    class HangWs:
        async def recv(self):
            await asyncio.sleep(3600)

    from janissary.integrations.websocket_learn import _collect_s2c_with_timing

    async def run():
        return await _collect_s2c_with_timing(
            HangWs(), quiet_s=0.05, total_budget_s=0.2
        )

    frames, first_s = asyncio.run(run())
    assert frames == [], f"expected no frames, got {frames!r}"
    assert first_s is None, (
        f"first_s must be None when no frame arrived, got {first_s!r}"
    )
def test_probe_populates_response_time():
    """probe() must pass _collect_s2c_with_timing's first_s to ProbeResult.

    FN-21 verification criterion 1. This test fails until probe() is
    wired to call _collect_s2c_with_timing; the other four tests verify
    the primitives but not the integration.
    """
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, patch
    from janissary.integrations.websocket_learn import probe

    fake_ws = SimpleNamespace(
        send=AsyncMock(),
        recv=AsyncMock(),
        close=AsyncMock(),
    )
    msg = SimpleNamespace(direction="c2s", payload='{"a":"orig"}')
    seq = SimpleNamespace(messages=[msg])
    field = SimpleNamespace(path="a", message_index=0)
    model = SimpleNamespace(
        injectable_fields=[field],
        baseline_sequence=seq,
    )

    async def run():
        with patch(
            "janissary.integrations.websocket_learn._connect",
            new=AsyncMock(return_value=fake_ws),
        ), patch(
            "janissary.integrations.websocket_learn._replay_prefix",
            new=AsyncMock(),
        ), patch(
            "janissary.integrations.websocket_learn._collect_s2c",
            new=AsyncMock(return_value=["fallback"]),
        ), patch(
            "janissary.integrations.websocket_learn._collect_s2c_with_timing",
            new=AsyncMock(return_value=(["resp"], 0.42)),
        ):
            return await probe(
                "ws://test/", model,
                payloads=[("p1", "payload_val", "sqli")],
                max_probes=1,
            )

    results = asyncio.run(run())
    assert len(results) == 1, f"expected 1 result, got {len(results)}"
    assert results[0].response_time == 0.42, (
        f"probe() must populate response_time from "
        f"_collect_s2c_with_timing; got {results[0].response_time!r}"
    )

# --- FN-21 gap 4: baseline RTT sampling + std-dev ---


def test_learned_model_has_baseline_rtt_field():
    """LearnedModel exposes baseline_rtt, default empty dict.

    Shape: dict[int, tuple[float, float, int]] mapping message_index
    to (mean_seconds, stddev_seconds, n_samples). Empty when no
    baseline timing was captured.
    """
    from janissary.protocols.websocket import LearnedModel, MessageSequence

    m = LearnedModel(
        wire_format="json",
        baseline_sequence=MessageSequence(),
    )
    assert hasattr(m, "baseline_rtt"), (
        "LearnedModel must expose baseline_rtt (FN-21 gap 4)"
    )
    assert m.baseline_rtt == {}, (
        f"baseline_rtt default must be empty dict, got {m.baseline_rtt!r}"
    )

    m2 = LearnedModel(
        wire_format="json",
        baseline_sequence=MessageSequence(),
        baseline_rtt={0: (0.05, 0.01, 3)},
    )
    assert m2.baseline_rtt[0] == (0.05, 0.01, 3)


def test_rtt_stats_mean_and_pstdev():
    """_rtt_stats returns (mean, population_stddev, n) for >=2 samples."""
    from janissary.integrations.websocket_learn import _rtt_stats

    mean, std, n = _rtt_stats([0.10, 0.12, 0.14])
    assert n == 3
    assert abs(mean - 0.12) < 1e-6, f"mean: {mean!r}"
    # population stddev of [0.10, 0.12, 0.14] = sqrt((4e-4+0+4e-4)/3) ≈ 0.01633
    assert abs(std - 0.01633) < 1e-3, f"std: {std!r}"


def test_rtt_stats_handles_empty_and_single():
    """Edge cases: empty list -> zeros; single sample -> std=0."""
    from janissary.integrations.websocket_learn import _rtt_stats

    assert _rtt_stats([]) == (0.0, 0.0, 0)
    mean, std, n = _rtt_stats([0.05])
    assert n == 1
    assert abs(mean - 0.05) < 1e-6
    assert std == 0.0


def test_capture_baseline_timing_returns_stats():
    """_capture_baseline_timing returns (mean, std, n) per c2s message index."""
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, patch
    from janissary.integrations.websocket_learn import _capture_baseline_timing

    class TimedWs:
        def __init__(self):
            self._recv_count = 0
        async def send(self, payload):
            self._recv_count = 0
        async def recv(self):
            if self._recv_count == 0:
                self._recv_count += 1
                await asyncio.sleep(0.02)
                return "resp"
            await asyncio.sleep(3600)
        async def close(self):
            pass

    async def fake_connect(*args, **kwargs):
        return TimedWs()

    seq = SimpleNamespace(
        messages=[
            SimpleNamespace(direction="c2s", payload='{"a":"x"}'),
            SimpleNamespace(direction="s2c", payload='{"a":"x"}'),
        ]
    )

    async def run():
        with patch(
            "janissary.integrations.websocket_learn._connect",
            new=AsyncMock(side_effect=fake_connect),
        ):
            return await _capture_baseline_timing(
                "ws://test/", seq, n_samples=3,
                timeout=0.5, quiet_s=0.05,
            )

    result = asyncio.run(run())
    assert 0 in result, f"expected message_index 0 in result; got {result!r}"
    mean, std, n = result[0]
    assert n == 3, f"expected 3 samples, got {n}"
    assert 0.005 < mean < 0.1, f"mean ~= 0.02s expected, got {mean!r}"
    assert isinstance(std, float)


def test_capture_baseline_timing_handles_connect_failure():
    """_capture_baseline_timing returns {} when _connect raises."""
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, patch
    from janissary.integrations.websocket_learn import _capture_baseline_timing

    async def failing_connect(*args, **kwargs):
        raise ConnectionRefusedError("test")

    seq = SimpleNamespace(
        messages=[SimpleNamespace(direction="c2s", payload="x")]
    )

    async def run():
        with patch(
            "janissary.integrations.websocket_learn._connect",
            new=AsyncMock(side_effect=failing_connect),
        ):
            return await _capture_baseline_timing(
                "ws://test/", seq, n_samples=2,
                timeout=0.2, quiet_s=0.05,
            )

    result = asyncio.run(run())
    assert result == {}, f"expected empty dict, got {result!r}"


def test_learn_populates_baseline_rtt():
    """learn() calls _capture_baseline_timing and stores the result.

    FN-21 verification criterion 2. RED until learn() is wired; the
    other tests verify the field and helper but not the wiring.
    """
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, patch
    from janissary.integrations.websocket_learn import learn

    fake_ws = SimpleNamespace(
        send=AsyncMock(),
        recv=AsyncMock(),
        close=AsyncMock(),
    )

    async def fake_connect(*args, **kwargs):
        return fake_ws

    fake_stats = {0: (0.05, 0.005, 3)}
    fake_field = SimpleNamespace(path="a", message_index=0)

    async def run():
        with patch(
            "janissary.integrations.websocket_learn._connect",
            new=AsyncMock(side_effect=fake_connect),
        ), patch(
            "janissary.integrations.websocket_learn._collect_s2c",
            new=AsyncMock(return_value=["echo"]),
        ), patch(
            "janissary.integrations.websocket_learn.detect_wire_format",
            return_value="json",
        ), patch(
            "janissary.integrations.websocket_learn.find_injectable_fields",
            return_value=[fake_field],
        ), patch(
            "janissary.integrations.websocket_learn._capture_baseline_timing",
            new=AsyncMock(return_value=fake_stats),
        ):
            return await learn(
                "ws://test/", payloads=['{"a":"x"}'],
                n_samples=3,
            )

    model = asyncio.run(run())
    assert model.baseline_rtt == fake_stats, (
        f"learn() must populate baseline_rtt via _capture_baseline_timing; "
        f"got {model.baseline_rtt!r}"
    )
# --- FN-21 gaps 1+3+5: timing delta classification + caller guard + no_delta ---


def test_timing_differs_none_probe_time():
    """Probe with response_time=None cannot differ (no measurement)."""
    from janissary.integrations.websocket_learn import _timing_differs

    p = _probe(response_frames=(), payload_value="x", response_time=None)
    assert _timing_differs(p, baseline_mean=0.1, baseline_stddev=0.02) is False


def test_timing_differs_within_noise():
    """Small delta within noise does not fire timing_delta."""
    from janissary.integrations.websocket_learn import _timing_differs

    # 0.2s vs 0.1s mean, 0.05s std -> z=2.0, delta=0.1s. Both below thresholds.
    p = _probe(response_frames=(), payload_value="x", response_time=0.2)
    assert _timing_differs(p, baseline_mean=0.1, baseline_stddev=0.05) is False


def test_timing_differs_significant():
    """Large statistical AND absolute delta fires timing_delta."""
    from janissary.integrations.websocket_learn import _timing_differs

    # 2.0s vs 0.1s mean, 0.05s std -> z=38, delta=1.9s. Both above thresholds.
    p = _probe(response_frames=(), payload_value="x", response_time=2.0)
    assert _timing_differs(p, baseline_mean=0.1, baseline_stddev=0.05) is True


def test_timing_differs_faster_response():
    """Probe faster than baseline is NOT a delta (only slower is signal)."""
    from janissary.integrations.websocket_learn import _timing_differs

    # 0.05s vs 0.1s mean. Faster, not slower. No signal.
    p = _probe(response_frames=(), payload_value="x", response_time=0.05)
    assert _timing_differs(p, baseline_mean=0.1, baseline_stddev=0.05) is False


def test_timing_differs_below_absolute_floor():
    """Huge z-score but small absolute delta does not fire (absolute floor wins)."""
    from janissary.integrations.websocket_learn import _timing_differs

    # 0.3s vs 0.1s mean, 0.001s std -> z=200 but delta=0.2s < 0.5s floor.
    p = _probe(response_frames=(), payload_value="x", response_time=0.3)
    assert _timing_differs(p, baseline_mean=0.1, baseline_stddev=0.001) is False


def test_classify_delta_timing_delta():
    """Same content, timing_differs=True -> timing_delta."""
    from janissary.integrations.websocket_learn import _classify_delta

    p = _probe(response_frames=(), payload_value="X")
    kind = _classify_delta(
        p, baseline_norm="abc", probe_norm="abc",
        baseline_frame_count=1, probe_frame_count=1,
        timing_differs=True,
    )
    assert kind == "timing_delta", (
        f"identical content + timing_differs must be timing_delta; "
        f"got {kind!r}"
    )


def test_classify_delta_no_delta():
    """Same content, timing_differs=False -> no_delta (not content_delta)."""
    from janissary.integrations.websocket_learn import _classify_delta

    p = _probe(response_frames=(), payload_value="X")
    kind = _classify_delta(
        p, baseline_norm="abc", probe_norm="abc",
        baseline_frame_count=1, probe_frame_count=1,
        timing_differs=False,
    )
    assert kind == "no_delta", (
        f"identical content + timing_differs=False must be no_delta; "
        f"got {kind!r}"
    )


def test_verify_emits_timing_delta_candidate():
    """verify() emits a candidate when timing_delta fires on identical content.

    FN-21 verification criterion 3 (integration). RED until verify() is
    wired: today the content guard blocks classification, so no candidate.
    """
    from janissary.protocols.websocket import (
        LearnedModel, MessageSequence, WebSocketMessage, ProbeResult,
    )

    seq = MessageSequence(messages=[
        WebSocketMessage(direction="c2s", payload='{"a":"orig"}'),
        WebSocketMessage(direction="s2c", payload='{"a":"orig"}'),
    ])
    model = LearnedModel(
        wire_format="json",
        baseline_sequence=seq,
        injectable_fields=[],
        baseline_rtt={0: (0.1, 0.02, 5)},
    )
    p = ProbeResult(
        field_path="a", message_index=0, payload_name="sqli_quote",
        payload_value="'", category="sqli",
        original_payload='{"a":"orig"}',
        mutated_payload='{"a":"\'"}',
        response_frames=('{"a":"orig"}',),  # identical content
        sent_ok=True,
        response_time=2.0,  # 20x baseline mean, well above thresholds
    )
    from janissary.integrations.websocket_learn import verify

    candidates = verify([p], model, url="ws://test/socket")
    assert len(candidates) == 1, (
        f"timing_delta should emit exactly 1 candidate; got {len(candidates)}"
    )
    assert "timing_delta" in candidates[0].detail, (
        f"detail must carry timing_delta; got {candidates[0].detail!r}"
    )