"""WebSocket BaselineNormalizer (Phase 2.2 + FN-16 part 1).

WebSocket verification operates on *message sequences*, not single
frames. This module defines the data model for a captured sequence and
a normalizer that makes two sequences comparable.

Design note:
    NormalizedResponse.body is a canonical JSON array of frame records.
    Two MessageSequences that carry the same semantic traffic normalize
    to byte-identical bodies, regardless of frame timestamps or
    incidental key ordering. This is what lets the verify() phase
    (FN-16 part 4) diff sequences meaningfully.

    Stripped metadata lists what was removed (timing, per-message
    session tokens) so a finding can record "these were volatile and
    ignored" per Phase 0.3's transparency requirement.

See docs/PHASE-6-PLAN.md FN-16.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal

from .base import NormalizedResponse

Direction = Literal["c2s", "s2c"]  # client-to-server or server-to-client


@dataclass(frozen=True)
class WebSocketMessage:
    """One frame in a captured WebSocket session.

    ``direction`` is "c2s" (client sent) or "s2c" (server sent).
    ``payload`` is the raw text or decoded bytes (UTF-8 replacement).
    ``elapsed`` is seconds since session start; stripped by the normalizer.
    """

    direction: Direction
    payload: str
    elapsed: float = 0.0


@dataclass(frozen=True)
class MessageSequence:
    """A captured WebSocket session: ordered frames plus context.

    ``protocol`` is "websocket" (this module). Future protocol adapters
    reuse NormalizedResponse but not MessageSequence directly.
    """

    messages: list[WebSocketMessage] = field(default_factory=list)
    protocol: str = "websocket"


_VOLATILE_MESSAGE_KEYS = frozenset(
    {
        "timestamp",
        "ts",
        "time",
        "sent_at",
        "received_at",
        "session_id",
        "sessionId",
        "request_id",
        "requestId",
    }
)


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _normalize_payload(payload: str, stripped: list[str]) -> str:
    """Normalize one frame payload: parse JSON, strip volatile keys,
    re-canonicalize. Non-JSON payloads pass through unchanged (after
    whitespace collapse).

    Returns the canonical string form.
    """
    text = payload.strip()
    if not text:
        return ""
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        # Not JSON; treat as opaque text, collapse whitespace.
        import re as _re

        return _re.sub(r"\s+", " ", text)
    cleaned = _strip_volatile_keys(parsed, stripped)
    return _canonical_json(cleaned)


def _strip_volatile_keys(obj: Any, stripped: list[str]) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in _VOLATILE_MESSAGE_KEYS:
                marker = f"payload:key_stripped:{k}"
                if marker not in stripped:
                    stripped.append(marker)
                continue
            out[k] = _strip_volatile_keys(v, stripped)
        return out
    if isinstance(obj, list):
        return [_strip_volatile_keys(x, stripped) for x in obj]
    return obj


class WebSocketNormalizer:
    """BaselineNormalizer for WebSocket message sequences.

    Input: MessageSequence.
    Output: NormalizedResponse whose .body is a canonical JSON array of
    {direction, payload} objects (timing stripped, JSON keys sorted,
    volatile keys removed).

    Two sequences that carry the same semantic traffic produce
    identical .body strings. That equality is what the FN-16 verify
    phase (part 4) uses to distinguish signal from noise.
    """

    protocol_name = "websocket"

    def normalize(self, response: Any) -> NormalizedResponse:
        if not isinstance(response, MessageSequence):
            return NormalizedResponse(
                body="",
                length=0,
                status=None,
                stripped=("body:wrong_input_type",),
            )

        stripped: list[str] = []
        frames = []
        for msg in response.messages:
            norm_payload = _normalize_payload(msg.payload, stripped)
            frames.append(
                {
                    "direction": msg.direction,
                    "payload": norm_payload,
                }
            )

        # Per-frame timing is always dropped from the canonical form;
        # record its presence once (not per frame) to avoid noise.
        if any(m.elapsed for m in response.messages):
            stripped.append("body:timing_dropped")

        body = _canonical_json(frames)
        return NormalizedResponse(
            body=body,
            length=len(body),
            status=None,  # WebSocket sessions do not have an HTTP status
            headers={},
            stripped=tuple(stripped),
        )


WireFormat = Literal["json", "xml", "text", "unknown"]


@dataclass(frozen=True)
class InjectableField:
    """A single leaf value in a c2s message that a probe can replace.

    ``message_index`` is the position within ``MessageSequence.messages``
    (0-indexed, counts both c2s and s2c frames, so the value distinguishes
    which specific frame this field belongs to).

    ``path`` uses dotted notation with bracket array indexing:
    ``user.id``, ``items[0].name``, ``.config.timeout``.

    ``value_kind`` is the JSON type of the leaf: string, integer, float.
    Booleans and nulls are not injectable (not payload carriers).
    """

    message_index: int
    path: str
    value_kind: str
    original_value: Any


@dataclass(frozen=True)
class LearnedModel:
    """Output of learn(): what to probe against this target.

    Produced by ``integrations.websocket_learn.learn()`` (FN-16 part 3),
    consumed by the probe phase (part 4) and the verifier (part 5).

    ``injectable_fields`` is ordered by message index then by JSON
    traversal order (depth-first). Callers that want deterministic
    fuzzing order rely on this.
    """

    wire_format: WireFormat
    baseline_sequence: MessageSequence
    injectable_fields: list[InjectableField] = field(default_factory=list)
    notes: tuple[str, ...] = ()
    baseline_rtt: dict[int, tuple[float, float, int]] = field(default_factory=dict)


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of one (field, payload) probe.

    ``field_path`` and ``message_index`` identify which injectable
    field was mutated (matching InjectableField fields).

    ``original_payload`` is the pre-mutation c2s payload; ``mutated_payload``
    is what was actually sent after set_field_value() applied the injection.

    ``response_frames`` is what the server sent after the mutated payload
    (decoded strings). Empty tuple when server was silent.

    ``sent_ok=False`` means the send or connection failed; ``error_note``
    then describes why. Probe results with sent_ok=False carry no signal
    and should be ignored by verify().
    """

    field_path: str
    message_index: int
    payload_name: str
    payload_value: str
    category: str
    original_payload: str
    mutated_payload: str
    response_frames: tuple[str, ...]
    sent_ok: bool
    error_note: str | None = None
    response_time: float | None = None

    def to_dict(self) -> dict:
        return {
            "field_path": self.field_path,
            "message_index": self.message_index,
            "payload_name": self.payload_name,
            "payload_value": self.payload_value,
            "category": self.category,
            "original_payload": self.original_payload,
            "mutated_payload": self.mutated_payload,
            "response_frames": list(self.response_frames),
            "sent_ok": self.sent_ok,
            "error_note": self.error_note,
            "response_time": self.response_time,
        }
