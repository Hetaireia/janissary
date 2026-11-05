"""WebSocket discovery module (Phase 2.2 + FN-16 part 5).

Wraps probe() + verify() into a single discover() entry point.
Produces CandidateFinding objects; does not emit. Emission happens
through VerificationEngine (see WebSocketReconConfirmer).

Design template: GraphQLDiscoveryModule (integrations/graphql_discovery.py).
Differences driven by protocol:
- GraphQL discovery holds a persistent client; WebSocket discovery holds
  a URL and a LearnedModel (probe() opens fresh connections).
- GraphQL discovery has three "always / optional / opt-in" tiers; WebSocket
  discovery has one tier because probe() is the only action.

See docs/PHASE-6-PLAN.md FN-16.
"""

from __future__ import annotations

from janissary.protocols.websocket import LearnedModel
from janissary.verification import CandidateFinding

from .websocket_learn import probe, verify


class WebSocketDiscoveryModule:
    """Produce CandidateFinding objects by probing a learned WebSocket model."""

    def __init__(
        self,
        url: str,
        model: LearnedModel,
        payloads: list[tuple[str, str, str]] | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.url = url
        self.model = model
        self.payloads = payloads
        self.timeout = timeout

    async def discover(
        self,
        max_probes: int | None = 50,
        response_quiet_s: float = 1.0,
    ) -> list[CandidateFinding]:
        """Run probe() then verify(); return candidates.

        max_probes caps (field x payload) pairs; default 50.
        response_quiet_s is the quiet period after each send before
        moving to the next probe.
        """
        probes = await probe(
            self.url,
            self.model,
            payloads=self.payloads,
            timeout=self.timeout,
            response_quiet_s=response_quiet_s,
            max_probes=max_probes,
        )
        return verify(probes, self.model, url=self.url)
