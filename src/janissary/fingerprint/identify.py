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


def _merge_signals(signals):
    """Merge per-sample matcher results into a single Field."""
    valid = [s for s in signals if s is not None]
    if not valid:
        return Field(value=None, confidence=0.0, evidence=[])
    values = {s[0] for s in valid}
    evidence = []
    for s in valid:
        evidence.extend(s[2])
    if len(values) > 1:
        return Field(value="Ambiguous", confidence=0.50, evidence=evidence)
    v = values.pop()
    if v == "Ambiguous":
        return Field(value="Ambiguous", confidence=0.50, evidence=evidence)
    conf = min(s[1] for s in valid)
    return Field(value=v, confidence=conf, evidence=evidence)


def identify(baselines):
    """Classify the target stack from baseline headers."""
    headers_list = []
    for baseline in baselines:
        headers_list.extend(baseline.headers)
    if not headers_list:
        return StackProfile()
    return StackProfile(
        server=_merge_signals([match_server(h) for h in headers_list]),
        framework=_merge_signals([match_framework(h) for h in headers_list]),
        language=_merge_signals([match_language(h) for h in headers_list]),
        waf=_merge_signals([match_waf(h) for h in headers_list]),
        cdn=_merge_signals([match_cdn(h) for h in headers_list]),
    )
