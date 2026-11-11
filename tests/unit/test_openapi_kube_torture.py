"""Kubernetes torture test for the OpenAPI parser (ADR-030 Stage 3).

The Kubernetes swagger.json is ~4.3 MB Swagger 2.0 with 1172 operations
and heavy $ref usage. It is fetched on demand and gitignored; this
test skips with an explicit message if the file is absent.

    python tools/fetch_kube_spec.py

No prance differential exists for this fixture. prance cannot parse
the Kubernetes spec: its ref discoverer treats every $ref key as a URL
reference, and Kubernetes uses $ref as a JSON Schema property name
(e.g. ObjectReference.ref -> {"type": "string"}). The crash is
AttributeError: 'dict' object has no attribute 'decode' inside
prance.util.resolver._discover_refs. JANISSARY resolves refs only in
path items and parameter entries, never inside schemas, so it is
unaffected. The expected count below was measured once from
JANISSARY and cross-checked against the raw path/method enumeration.
"""

import time
import tracemalloc

import pytest

from janissary.importers.openapi import parse_spec

FIXTURE = "tests/fixtures/openapi/large/kube-openapi.json"
EXPECTED_OPERATIONS = 1172
MEMORY_CEILING_MB = 100


def _fixture_available():
    from pathlib import Path

    return Path(FIXTURE).is_file()


@pytest.mark.skipif(
    not _fixture_available(),
    reason=(
        "Kubernetes spec not present; run python tools/fetch_kube_spec.py to fetch it"
    ),
)
def test_kube_operations_and_memory():
    tracemalloc.start()
    t0 = time.time()
    result = parse_spec(FIXTURE)
    elapsed = time.time() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_mb = peak / 1024 / 1024

    assert result.spec_version == "swagger 2.0"
    assert len(result.imported) == EXPECTED_OPERATIONS
    assert len(result.skipped) == 0
    assert len(result.notes) == 0
    assert peak_mb < MEMORY_CEILING_MB, (
        "peak "
        + str(round(peak_mb, 1))
        + " MB exceeds "
        + str(MEMORY_CEILING_MB)
        + " MB ceiling"
    )
    assert elapsed < 10, (
        "parse took " + str(round(elapsed, 2)) + " s; expected well under 10"
    )
