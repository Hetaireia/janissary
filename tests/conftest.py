"""Shared pytest fixtures for the JANISSARY test suite.

The CLI gates network-touching commands (scan, fingerprint, graphql, ws,
admin) behind a Terms-of-Use acceptance check (see ``janissary.legal``).
On a developer machine the marker file in the user's home directory
satisfies the gate; on a fresh CI runner there is no marker, so any test
that invokes ``cli.main([...])`` exits 64 before reaching the code under
test.

This fixture bridges the gap:

- For tests that exercise CLI behavior: set ``JANISSARY_ACCEPT_TERMS=1``
  so the gate short-circuits (documented non-interactive acceptance path).

- For ``tests/unit/test_legal.py``: the tests there exercise the gate
  itself and require the env var to be *unset* so the non-TTY / bad-token
  paths can raise SystemExit as designed. Explicitly delenv for that file.

Scoped per-test via ``monkeypatch``, so no cross-test contamination.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _janissary_terms_env(monkeypatch, request):
    """Ensure CLI-invoking tests have terms accepted, and gate tests don't."""
    if request.path.name == "test_legal.py":
        # Gate tests: env var must be unset so SystemExit paths fire.
        monkeypatch.delenv("JANISSARY_ACCEPT_TERMS", raising=False)
    else:
        # Everything else: env var on so CLI reaches code under test.
        monkeypatch.setenv("JANISSARY_ACCEPT_TERMS", "1")
