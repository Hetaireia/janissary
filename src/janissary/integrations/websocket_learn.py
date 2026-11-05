"""WebSocket learn — algorithms and orchestration (Phase 2.2 + FN-16 parts 2-3).

Part 2 (pure algorithms): detect_wire_format, find_injectable_fields, set_field_value.
Part 3 (async orchestration): learn().

Design notes for learn():
- Caller MUST provide payloads. The scanner cannot construct valid
  WebSocket messages without knowing the target's API. Empty payloads
  yields an honest-empty LearnedModel with note
  "no_probe_payloads_provided" -- not a fabricated "clean" result.
- A brief passive window precedes active probing to capture any
  spontaneous server traffic.
- After each c2s payload, s2c responses are collected until a quiet
  period (response_quiet_s) or an overall timeout.

See docs/PHASE-6-PLAN.md FN-16.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import time
from typing import Any

from janissary.protocols.websocket import (
    InjectableField,
    LearnedModel,
    MessageSequence,
    ProbeResult,
    WebSocketMessage,
    WebSocketNormalizer,
    WireFormat,
)
from janissary.verification import CandidateFinding

from .websocket import _connect

_XML_PREFIX_RE = re.compile(r"^\s*<\?xml", re.IGNORECASE)


# ===========================================================================
# Part 2: pure algorithms
# ===========================================================================


def detect_wire_format(sequence: MessageSequence) -> WireFormat:
    """Determine the wire format from c2s messages."""
    c2s_payloads = [m.payload for m in sequence.messages if m.direction == "c2s"]
    non_empty = [p.strip() for p in c2s_payloads if p.strip()]
    if not non_empty:
        return "unknown"

    if _XML_PREFIX_RE.match(non_empty[0]):
        return "xml"

    json_parses = 0
    for p in non_empty:
        try:
            parsed = json.loads(p)
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, (dict, list)):
            json_parses += 1

    if json_parses * 2 >= len(non_empty):
        return "json"
    return "text"


def _join_path(prefix: str, segment: str) -> str:
    if not prefix:
        return segment
    return prefix + "." + segment


def _join_index(prefix: str, index: int) -> str:
    return f"{prefix}[{index}]"


def _walk_injectables(
    value: Any,
    prefix: str,
    message_index: int,
    out: list[InjectableField],
) -> None:
    if isinstance(value, bool):
        return
    if value is None:
        return
    if isinstance(value, str):
        out.append(
            InjectableField(
                message_index=message_index,
                path=prefix,
                value_kind="string",
                original_value=value,
            )
        )
        return
    if isinstance(value, int):
        out.append(
            InjectableField(
                message_index=message_index,
                path=prefix,
                value_kind="integer",
                original_value=value,
            )
        )
        return
    if isinstance(value, float):
        out.append(
            InjectableField(
                message_index=message_index,
                path=prefix,
                value_kind="float",
                original_value=value,
            )
        )
        return
    if isinstance(value, dict):
        for k in sorted(value.keys()):
            _walk_injectables(value[k], _join_path(prefix, k), message_index, out)
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _walk_injectables(item, _join_index(prefix, i), message_index, out)
        return


def find_injectable_fields(sequence: MessageSequence) -> list[InjectableField]:
    """Enumerate leaf fields in c2s JSON messages that a probe can mutate."""
    out: list[InjectableField] = []
    for msg_index, msg in enumerate(sequence.messages):
        if msg.direction != "c2s":
            continue
        payload = msg.payload.strip()
        if not payload:
            continue
        try:
            parsed = json.loads(payload)
        except (ValueError, TypeError):
            continue
        if not isinstance(parsed, (dict, list)):
            continue
        _walk_injectables(parsed, "", msg_index, out)
    return out


def _split_path(path: str) -> list[tuple[str, Any]]:
    steps: list[tuple[str, Any]] = []
    i = 0
    n = len(path)
    buf = ""
    while i < n:
        ch = path[i]
        if ch == ".":
            if buf:
                steps.append(("key", buf))
                buf = ""
            i += 1
        elif ch == "[":
            if buf:
                steps.append(("key", buf))
                buf = ""
            j = path.find("]", i)
            if j < 0:
                raise ValueError(f"unclosed bracket in path: {path!r}")
            try:
                idx = int(path[i + 1 : j])
            except ValueError as exc:
                raise ValueError(f"non-integer index in path: {path!r}") from exc
            steps.append(("index", idx))
            i = j + 1
        else:
            buf += ch
            i += 1
    if buf:
        steps.append(("key", buf))
    return steps


def set_field_value(payload: str, path: str, new_value: Any) -> str:
    """Mutate one leaf in a JSON payload; return canonical JSON."""
    try:
        parsed = json.loads(payload)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"payload is not valid JSON: {exc}") from exc

    steps = _split_path(path)
    if not steps:
        raise ValueError(f"empty path: {path!r}")

    node: Any = parsed
    for kind, seg in steps[:-1]:
        if kind == "key":
            if not isinstance(node, dict) or seg not in node:
                raise ValueError(f"path segment {seg!r} not found")
            node = node[seg]
        else:
            if not isinstance(node, list) or not (0 <= seg < len(node)):
                raise ValueError(f"list index {seg} out of range")
            node = node[seg]

    last_kind, last_seg = steps[-1]
    if last_kind == "key":
        if not isinstance(node, dict) or last_seg not in node:
            raise ValueError(f"final key {last_seg!r} not found")
        existing = node[last_seg]
    else:
        if not isinstance(node, list) or not (0 <= last_seg < len(node)):
            raise ValueError(f"final index {last_seg} out of range")
        existing = node[last_seg]

    if isinstance(existing, (dict, list)):
        raise ValueError(f"leaf target is a container: {path!r}")

    if last_kind == "key":
        node[last_seg] = new_value
    else:
        node[last_seg] = new_value

    return json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ===========================================================================
# Part 3: async orchestration
# ===========================================================================


def _decode_frame(frame) -> str:
    if isinstance(frame, str):
        return frame
    if isinstance(frame, (bytes, bytearray)):
        return frame.decode("utf-8", "replace")
    return str(frame)


async def _collect_s2c(
    ws,
    quiet_s: float,
    total_budget_s: float,
) -> list[str]:
    """Collect s2c frames until quiet_s passes without a new message,
    or total_budget_s elapses."""
    out: list[str] = []
    start = time.perf_counter()
    while True:
        remaining = total_budget_s - (time.perf_counter() - start)
        if remaining <= 0:
            break
        wait_for = min(quiet_s, remaining)
        try:
            frame = await asyncio.wait_for(ws.recv(), timeout=wait_for)
        except asyncio.TimeoutError:
            break
        out.append(_decode_frame(frame))
    return out


async def _collect_s2c_with_timing(
    ws,
    quiet_s: float,
    total_budget_s: float,
) -> tuple[list[str], float | None]:
    """Collect s2c frames and report elapsed seconds to first frame.

    Same loop as _collect_s2c, but also returns the elapsed time from
    function entry to the first successful recv() (perf_counter-based).
    Returns (frames, first_frame_elapsed_s); first_frame_elapsed_s is
    None if no frame arrived before timeout. Used by probe() to capture
    per-probe response time (FN-21 gap 2).
    """
    out: list[str] = []
    start = time.perf_counter()
    first_s: float | None = None
    while True:
        remaining = total_budget_s - (time.perf_counter() - start)
        if remaining <= 0:
            break
        wait_for = min(quiet_s, remaining)
        try:
            frame = await asyncio.wait_for(ws.recv(), timeout=wait_for)
        except asyncio.TimeoutError:
            break
        if first_s is None:
            first_s = time.perf_counter() - start
        out.append(_decode_frame(frame))
    return out, first_s


def _rtt_stats(samples: list[float]) -> tuple[float, float, int]:
    """Return (mean, population_stddev, n) for a list of RTT samples.

    Empty list -> (0.0, 0.0, 0). Single sample -> (mean, 0.0, 1).
    Population stddev (not sample stddev): we treat the samples as the
    complete set, not a subset drawn from a larger population. This
    makes the stddev the honest "spread of what we observed" and avoids
    the small-sample bias that sample-stddev would introduce at n=2.
    """
    import statistics

    n = len(samples)
    if n == 0:
        return (0.0, 0.0, 0)
    if n == 1:
        return (samples[0], 0.0, 1)
    return (statistics.mean(samples), statistics.pstdev(samples), n)


async def _capture_baseline_timing(
    url: str,
    sequence,
    n_samples: int,
    timeout: float = 10.0,
    quiet_s: float = 1.0,
    origin: str | None = None,
    headers: dict | None = None,
) -> dict[int, tuple[float, float, int]]:
    """Sample per-message-index round-trip times against the baseline.

    For each c2s message in sequence, replays all preceding c2s messages
    plus the target c2s message on a fresh connection, then measures
    elapsed seconds until the first s2c frame. Repeats n_samples times.
    A single connection is reused across samples for efficiency; each
    probe cycle resets send state naturally because the c2s send is the
    timing trigger.

    Returns {message_index: (mean_s, pstdev_s, n)}. Indices with no
    successful sample are omitted. Returns {} on connect failure so the
    caller can fall back to no-timing behavior.

    FN-21 gap 4: this is the source of LearnedModel.baseline_rtt that
    gap 3's caller guard will consume.
    """
    try:
        ws = await _connect(url, timeout=timeout, origin=origin, headers=headers)
    except Exception:
        return {}

    samples_by_index: dict[int, list[float]] = {}
    try:
        c2s_indices = [
            i for i, m in enumerate(sequence.messages) if m.direction == "c2s"
        ]
        for idx in c2s_indices:
            samples_by_index[idx] = []

        for _ in range(n_samples):
            for idx in c2s_indices:
                try:
                    for pre in sequence.messages[: idx + 1]:
                        if pre.direction == "c2s":
                            await ws.send(pre.payload)
                    _, first_s = await _collect_s2c_with_timing(
                        ws, quiet_s=quiet_s, total_budget_s=timeout
                    )
                    if first_s is not None:
                        samples_by_index[idx].append(first_s)
                except Exception:
                    continue
    finally:
        with contextlib.suppress(Exception):
            await ws.close()

    result: dict[int, tuple[float, float, int]] = {}
    for idx, samples in samples_by_index.items():
        if samples:
            result[idx] = _rtt_stats(samples)
    return result


async def learn(
    url: str,
    payloads: list[str],
    timeout: float = 10.0,
    origin: str | None = None,
    headers: dict | None = None,
    passive_window_s: float = 1.5,
    response_quiet_s: float = 1.0,
    n_samples: int = 3,
) -> LearnedModel:
    """Learn a target's WebSocket message structure.

    See module docstring for design rationale and constraints.
    """
    if not payloads:
        return LearnedModel(
            wire_format="unknown",
            baseline_sequence=MessageSequence(),
            injectable_fields=[],
            notes=("no_probe_payloads_provided",),
        )

    try:
        ws = await _connect(url, timeout=timeout, origin=origin, headers=headers)
    except Exception as exc:
        return LearnedModel(
            wire_format="unknown",
            baseline_sequence=MessageSequence(),
            injectable_fields=[],
            notes=(f"connect_failed: {type(exc).__name__}: {exc}",),
        )

    messages: list[WebSocketMessage] = []
    session_start = time.perf_counter()

    def _elapsed() -> float:
        return time.perf_counter() - session_start

    try:
        passive_frames = await _collect_s2c(
            ws, quiet_s=response_quiet_s, total_budget_s=passive_window_s
        )
        for frame in passive_frames:
            messages.append(
                WebSocketMessage(direction="s2c", payload=frame, elapsed=_elapsed())
            )

        for payload in payloads:
            try:
                await ws.send(payload)
            except Exception as exc:
                messages.append(
                    WebSocketMessage(
                        direction="c2s",
                        payload=f"<send_error: {type(exc).__name__}>",
                        elapsed=_elapsed(),
                    )
                )
                continue
            messages.append(
                WebSocketMessage(direction="c2s", payload=payload, elapsed=_elapsed())
            )
            s2c_frames = await _collect_s2c(
                ws, quiet_s=response_quiet_s, total_budget_s=timeout
            )
            for frame in s2c_frames:
                messages.append(
                    WebSocketMessage(direction="s2c", payload=frame, elapsed=_elapsed())
                )
    finally:
        with contextlib.suppress(Exception):
            await ws.close()

    sequence = MessageSequence(messages=messages)
    wire_format = detect_wire_format(sequence)
    fields = find_injectable_fields(sequence)

    notes_list: list[str] = []
    if not fields:
        notes_list.append("no_injectable_fields_found")

    baseline_rtt: dict[int, tuple[float, float, int]] = {}
    try:
        baseline_rtt = await _capture_baseline_timing(
            url,
            sequence,
            n_samples=n_samples,
            timeout=timeout,
            quiet_s=response_quiet_s,
            origin=origin,
            headers=headers,
        )
    except Exception:
        pass

    return LearnedModel(
        wire_format=wire_format,
        baseline_sequence=sequence,
        injectable_fields=fields,
        notes=tuple(notes_list),
        baseline_rtt=baseline_rtt,
    )


# ===========================================================================
# Part 4: probe orchestration
# ===========================================================================


WS_PROBE_PAYLOADS: list[tuple[str, str, str]] = [
    # (name, value, category)
    ("sqli_quote", "'", "sqli"),
    ("sqli_or_1eq1", "' OR '1'='1", "sqli"),
    ("sqli_union_null", "' UNION SELECT NULL--", "sqli"),
    ("sqli_sleep", "' OR SLEEP(5)--", "sqli"),
    ("xss_script", "<script>alert(1)</script>", "xss"),
    ("xss_img", "<img src=x onerror=alert(1)>", "xss"),
    ("traversal_passwd", "../../../etc/passwd", "traversal"),
    ("traversal_encoded", "..%2f..%2f..%2fetc%2fpasswd", "traversal"),
    ("cmdi_semicolon", "; id", "cmdi"),
    ("cmdi_pipe", "| whoami", "cmdi"),
    ("generic_null_byte", "\x00", "injection"),
]


async def _replay_prefix(
    ws,
    messages: list[WebSocketMessage],
    upto_exclusive: int,
    drain_quiet_s: float,
) -> None:
    """Send every c2s message before upto_exclusive, draining s2c between."""
    for msg in messages[:upto_exclusive]:
        if msg.direction != "c2s":
            continue
        try:
            await ws.send(msg.payload)
        except Exception:
            return
        # Drain any s2c responses the replay triggered, with a short
        # quiet window, so the mutated probe's response is not mixed
        # with replay-response frames.
        await _collect_s2c(ws, quiet_s=drain_quiet_s, total_budget_s=drain_quiet_s * 4)


async def probe(
    url: str,
    model: LearnedModel,
    payloads: list[tuple[str, str, str]] | None = None,
    timeout: float = 10.0,
    origin: str | None = None,
    headers: dict | None = None,
    response_quiet_s: float = 1.0,
    max_probes: int | None = 50,
) -> list[ProbeResult]:
    """Mutate each injectable field with each payload and record responses.

    Fresh connection per probe. For multi-message models, all c2s
    messages before the mutated one are replayed first (s2c drained
    between), so the mutated message lands in the expected session state.

    ``max_probes`` caps total probes across (field, payload) pairs.
    Default 50 keeps runtime bounded for models with many fields.
    Set to None to disable (careful: N_fields * N_payloads probes).

    Probe results with ``sent_ok=False`` carry no signal; verify()
    must ignore them.
    """
    if not model.injectable_fields:
        return []

    payload_lib = payloads if payloads is not None else WS_PROBE_PAYLOADS
    if not payload_lib:
        return []

    results: list[ProbeResult] = []
    count = 0
    drain_quiet_s = min(0.2, response_quiet_s)

    for field in model.injectable_fields:
        # Original payload is the c2s frame at field.message_index.
        if not (0 <= field.message_index < len(model.baseline_sequence.messages)):
            continue
        orig_msg = model.baseline_sequence.messages[field.message_index]
        if orig_msg.direction != "c2s":
            continue
        original_payload = orig_msg.payload

        for payload_name, payload_value, category in payload_lib:
            if max_probes is not None and count >= max_probes:
                return results
            count += 1

            try:
                mutated = set_field_value(original_payload, field.path, payload_value)
            except ValueError as exc:
                results.append(
                    ProbeResult(
                        field_path=field.path,
                        message_index=field.message_index,
                        payload_name=payload_name,
                        payload_value=payload_value,
                        category=category,
                        original_payload=original_payload,
                        mutated_payload="",
                        response_frames=(),
                        sent_ok=False,
                        error_note=f"mutation_failed: {exc}",
                    )
                )
                continue

            try:
                ws = await _connect(
                    url, timeout=timeout, origin=origin, headers=headers
                )
            except Exception as exc:
                results.append(
                    ProbeResult(
                        field_path=field.path,
                        message_index=field.message_index,
                        payload_name=payload_name,
                        payload_value=payload_value,
                        category=category,
                        original_payload=original_payload,
                        mutated_payload=mutated,
                        response_frames=(),
                        sent_ok=False,
                        error_note=f"connect_failed: {type(exc).__name__}",
                    )
                )
                continue

            try:
                await _replay_prefix(
                    ws,
                    model.baseline_sequence.messages,
                    field.message_index,
                    drain_quiet_s=drain_quiet_s,
                )
                try:
                    await ws.send(mutated)
                except Exception as exc:
                    results.append(
                        ProbeResult(
                            field_path=field.path,
                            message_index=field.message_index,
                            payload_name=payload_name,
                            payload_value=payload_value,
                            category=category,
                            original_payload=original_payload,
                            mutated_payload=mutated,
                            response_frames=(),
                            sent_ok=False,
                            error_note=f"send_failed: {type(exc).__name__}",
                        )
                    )
                    continue
                s2c_frames, first_frame_s = await _collect_s2c_with_timing(
                    ws, quiet_s=response_quiet_s, total_budget_s=timeout
                )
                results.append(
                    ProbeResult(
                        field_path=field.path,
                        message_index=field.message_index,
                        payload_name=payload_name,
                        payload_value=payload_value,
                        category=category,
                        original_payload=original_payload,
                        mutated_payload=mutated,
                        response_frames=tuple(s2c_frames),
                        sent_ok=True,
                        response_time=first_frame_s,
                    )
                )
            finally:
                with contextlib.suppress(Exception):
                    await ws.close()

    return results


# ===========================================================================
# Part 5: verify orchestration
# ===========================================================================


def _extract_baseline_response(
    model: LearnedModel, message_index: int
) -> tuple[str, ...]:
    """Extract s2c frames that came after message_index's c2s message
    and before the next c2s message. These are the baseline responses
    the original (unmutated) payload produced."""
    msgs = model.baseline_sequence.messages
    out: list[str] = []
    for m in msgs[message_index + 1 :]:
        if m.direction == "c2s":
            break
        out.append(m.payload)
    return tuple(out)


def _seq_from_s2c_frames(frames: tuple[str, ...]) -> MessageSequence:
    """Build a MessageSequence of only s2c frames for normalization."""
    return MessageSequence(
        messages=[WebSocketMessage(direction="s2c", payload=f) for f in frames]
    )


TIMING_DELTA_MIN_Z = 3.0
TIMING_DELTA_MIN_ABSOLUTE_S = 0.5


def _timing_differs(
    probe: ProbeResult,
    baseline_mean: float,
    baseline_stddev: float,
) -> bool:
    """True when the probe was measurably slower than baseline.

    Two thresholds must both be satisfied:
    - absolute: probe slower by at least TIMING_DELTA_MIN_ABSOLUTE_S
    - statistical: delta / baseline_stddev >= TIMING_DELTA_MIN_Z (if stddev > 0)

    Never fires for probes that are faster than baseline (delta < 0).
    Never fires when response_time is None (no measurement taken).

    Consumed by verify()'s guard: a probe with identical content but
    statistically significant slower response can be a blind-injection
    candidate even though the response body is unchanged.
    """
    if probe.response_time is None:
        return False
    delta = probe.response_time - baseline_mean
    if delta < TIMING_DELTA_MIN_ABSOLUTE_S:
        return False
    if baseline_stddev > 0:
        if delta / baseline_stddev < TIMING_DELTA_MIN_Z:
            return False
    return True


def _classify_delta(
    probe: ProbeResult,
    baseline_norm: str,
    probe_norm: str,
    baseline_frame_count: int = 0,
    probe_frame_count: int = 0,
    timing_differs: bool = False,
) -> str:
    """Classify how probe_norm differs from baseline_norm.

    Four-way taxonomy, precedence highest-to-lowest:
      1. ``echoed_payload``: probe.payload_value appears in probe_norm
         but not baseline_norm (mutation reflected verbatim). Echo wins
         precedence because it is the most specific signal.
      2. ``frame_count_delta``: s2c frame counts differ.
      3. ``length_delta``: same count, normalized-body length differs.
      4. ``content_delta``: same count and length, content differs.

    Status and timing deltas are not tracked by verify() today. See
    the scoping note in docs/PHASE-6-PLAN.md (FN-16 follow-up) for why
    adding them is a multi-session change.
    """
    pv = probe.payload_value or ""
    if pv and pv in probe_norm and pv not in baseline_norm:
        return "echoed_payload"
    if baseline_frame_count != probe_frame_count:
        return "frame_count_delta"
    if len(baseline_norm) != len(probe_norm):
        return "length_delta"
    if baseline_norm != probe_norm:
        return "content_delta"
    if timing_differs:
        return "timing_delta"
    return "no_delta"


def _probe_to_candidate(
    probe: ProbeResult,
    url: str,
    delta_kind: str | None = None,
) -> CandidateFinding:
    detail = (
        f"Probe on {probe.field_path!r} (msg {probe.message_index}, "
        f"payload {probe.payload_name}) produced a server response that "
        f"differs from baseline after normalization"
    )
    if delta_kind:
        detail += f" (delta: {delta_kind})"
    return CandidateFinding(
        param=probe.field_path,
        payload_name=probe.payload_name,
        payload_value=probe.payload_value,
        category="websocket",
        severity="medium",
        finding_type=f"websocket_{probe.category}_probe",
        detail=detail,
        url=url,
        method="WS",
    )


def verify(
    probes: list[ProbeResult],
    model: LearnedModel,
    url: str = "",
) -> list[CandidateFinding]:
    """Emit CandidateFindings for probes whose response differs from baseline.

    For each probe: extract the baseline response frames that followed
    the original (unmutated) c2s message at probe.message_index, normalize
    both baseline and probe responses via WebSocketNormalizer, and compare
    canonical bodies. Differing bodies yield a candidate.

    Probes with sent_ok=False carry no signal and are skipped.
    Probes with empty response_frames are also skipped in v1 -- a silent
    server gives no differential signal. This is a v1 limitation; see FN-16.

    Candidates carry finding_type=f"websocket_{category}_probe" so
    WebSocketReconConfirmer can route them to unproven.
    """
    if not probes:
        return []

    normalizer = WebSocketNormalizer()
    candidates: list[CandidateFinding] = []

    for p in probes:
        if not p.sent_ok:
            continue
        if not p.response_frames:
            continue

        baseline_frames = _extract_baseline_response(model, p.message_index)
        if not baseline_frames:
            # No baseline response to compare against -- skip
            continue

        baseline_seq = _seq_from_s2c_frames(baseline_frames)
        probe_seq = _seq_from_s2c_frames(p.response_frames)

        baseline_norm = normalizer.normalize(baseline_seq).body
        probe_norm = normalizer.normalize(probe_seq).body

        baseline_rtt = model.baseline_rtt.get(p.message_index)
        timing_differs = False
        if baseline_rtt is not None:
            mean, stddev, _n = baseline_rtt
            timing_differs = _timing_differs(p, mean, stddev)

        if baseline_norm != probe_norm or timing_differs:
            delta_kind = _classify_delta(
                p,
                baseline_norm,
                probe_norm,
                len(baseline_frames),
                len(p.response_frames),
                timing_differs=timing_differs,
            )
            # delta_kind cannot be "no_delta" here given the guard above,
            # but the check is defensive against future _classify_delta changes.
            if delta_kind != "no_delta":
                candidates.append(_probe_to_candidate(p, url, delta_kind))

    return candidates
