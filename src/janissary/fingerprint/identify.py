"""Passive stack identification from baseline headers."""

from __future__ import annotations

from .profile import Field, StackProfile
from .signatures import (
    match_cdn,
    match_framework,
    match_language,
    match_server,
    match_waf,
)


def _merge_signals(signals, total_samples: int) -> Field:
    """Merge per-sample matcher results into a single Field.

    Two or more distinct labels => Ambiguous at 0.50.
    Single label => confidence scaled by witness fraction
    (supporters / total_samples) so a lone witness among many
    non-voting samples drops below the STRONG threshold.
    """
    valid = [s for s in signals if s is not None]
    if not valid:
        return Field(value=None, confidence=0.0, evidence=[])

    votes: dict[str, list[tuple[float, list[str]]]] = {}
    for s in valid:
        label, conf, ev = s
        votes.setdefault(label, []).append((conf, ev))

    if len(votes) > 1:
        evidence: list[str] = []
        for _, _, ev in valid:
            evidence.extend(ev)
        return Field(value="Ambiguous", confidence=0.50, evidence=evidence)

    label = next(iter(votes))
    witnesses = votes[label]
    base_conf = min(conf for conf, _ in witnesses)
    fraction = len(witnesses) / total_samples if total_samples > 0 else 1.0
    scaled = base_conf * fraction

    evidence = []
    for _, ev in witnesses:
        evidence.extend(ev)

    return Field(value=label, confidence=scaled, evidence=evidence)


def identify(baselines):
    """Classify the target stack from baseline headers."""
    headers_list = []
    for baseline in baselines:
        headers_list.extend(baseline.headers)

    if not headers_list:
        return StackProfile()

    total = len(headers_list)
    return StackProfile(
        server=_merge_signals([match_server(h) for h in headers_list], total),
        framework=_merge_signals([match_framework(h) for h in headers_list], total),
        language=_merge_signals([match_language(h) for h in headers_list], total),
        waf=_merge_signals([match_waf(h) for h in headers_list], total),
        cdn=_merge_signals([match_cdn(h) for h in headers_list], total),
    )
