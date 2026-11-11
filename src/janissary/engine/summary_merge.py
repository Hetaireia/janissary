"""Aggregate ScanSummary objects from multiple dispatch targets (ADR-030 Stage 6).

One OpenAPI operation can declare parameters in several locations. Scanner's
inject_in is a single mode per instance, so dispatch.build_scan_targets emits
one target per location and Stage 6 constructs one Scanner per target. That
produces N ScanSummary objects which must aggregate into one before exit code
and reporting are derived.

Merge semantics, chosen deliberately:

  findings, total_requests   summed; findings dedupe by fingerprint
  params                     union, order preserved
  aborted, scan_incomplete   OR; first abort_reason wins
  baselines                  dict.update (param names are unique per location)
  waf, pacer                 first non-None (same host, one detection is
                             representative; summing delay stats would
                             describe no real scan)
  groups                     RECOMPUTED from the merged findings, never
                             carried over

Divergence from the cli.py precedent: _merge_graphql_into_scan and
_merge_ws_into_scan increment finding_count per append, but
_DedupedFindingsList.append silently returns on a duplicate fingerprint, so
finding_count can exceed len(findings). This merge sets finding_count from
len(findings) after the loop, which cannot overcount. The cli.py functions
are left as they are; changing them is not Stage 6's business.
"""

from __future__ import annotations

from janissary.engine.scanner import ScanSummary


def merge_scan_summaries(summaries: list[ScanSummary]) -> ScanSummary:
    """Merge N per-target summaries into one.

    Raises ValueError on an empty list: a target-less operation is a
    programming error, not an empty result.
    """
    if not summaries:
        raise ValueError("merge_scan_summaries requires at least one summary")

    first = summaries[0]
    merged = ScanSummary(
        target=first.target,
        params=[],
        method=first.method,
    )

    seen_params: dict[str, None] = {}
    for s in summaries:
        for p in s.params:
            seen_params.setdefault(p, None)

    for s in summaries:
        for f in s.findings:
            merged.findings.append(f)
        merged.total_requests += s.total_requests
        merged.baselines.update(s.baselines)
        if merged.waf is None and s.waf is not None:
            merged.waf = s.waf
        if merged.pacer is None and s.pacer is not None:
            merged.pacer = s.pacer
        if s.scan_incomplete and not merged.scan_incomplete:
            merged.scan_incomplete = True
            if not merged.abort_reason:
                merged.abort_reason = s.abort_reason or "scan incomplete"
        if s.aborted and not merged.aborted:
            merged.aborted = True
            merged.abort_reason = s.abort_reason or merged.abort_reason

    merged.params = list(seen_params.keys())
    merged.finding_count = len(merged.findings)

    from janissary.engine.grouping import group_findings

    merged.groups = group_findings(merged.findings)

    return merged
