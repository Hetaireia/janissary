"""Agent: the orchestrator.

Takes a target, fingerprints it, consults the platform knowledge base,
runs the appropriate modules, and records findings into a store.

This module does not reimplement any detection or exploitation logic.
It wires together:

- recon.fingerprint       -> identify the platform
- recon.WAFDetector       -> identify the WAF, if any
- recon.AdaptivePacer     -> throttle requests
- agent.platform_kb       -> decide which modules to run
- agent.finding_store     -> persist the results

The actual scanners are dispatched through a small adapter table, so
the agent can be tested with fakes without any live network.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .finding_store import Finding, FindingStore
from .platform_kb import known_platforms, plan_for

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class AgentRun:
    target: str
    platforms: list[str] = field(default_factory=list)
    waf: str | None = None
    plan: list[str] = field(default_factory=list)
    modules_run: list[str] = field(default_factory=list)
    modules_skipped: list[str] = field(default_factory=list)
    new_findings: int = 0
    total_findings: int = 0
    aborted: bool = False
    abort_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "platforms": list(self.platforms),
            "waf": self.waf,
            "plan": list(self.plan),
            "modules_run": list(self.modules_run),
            "modules_skipped": list(self.modules_skipped),
            "new_findings": self.new_findings,
            "total_findings": self.total_findings,
            "aborted": self.aborted,
            "abort_reason": self.abort_reason,
        }


# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------

# A module adapter takes (target, context) and returns a list of Finding.
ModuleAdapter = Callable[[str, dict], list[Finding]]

_AUTH_LOSS_THRESHOLD = 2  # consecutive 401s before abort (ADR-011 D3)


def _noop_adapter(target: str, context: dict) -> list[Finding]:
    """Default adapter: do nothing, produce nothing."""
    return []


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------


class Agent:
    def __init__(
        self,
        store: FindingStore,
        adapters: dict[str, ModuleAdapter] | None = None,
        fingerprinter: Callable[[str], Any] | None = None,
        allowed_platforms: list[str] | None = None,
        max_modules: int = 8,
        session: Any = None,
        auth_configured: bool = False,
    ) -> None:
        self.store = store
        self.adapters = dict(adapters or {})
        self.fingerprinter = fingerprinter
        self.allowed_platforms = (
            list(allowed_platforms) if allowed_platforms is not None else None
        )
        self.max_modules = max(1, int(max_modules))
        self.session = session
        self.auth_configured = auth_configured
        self._consecutive_401s = 0
        self._aborted = False
        self._abort_reason = ""
        if session is not None and auth_configured:
            session.hooks.setdefault("response", []).append(self._response_hook)

    # ------------------------------------------------------------------

    def _response_hook(self, response, *args, **kwargs):
        """ADR-011 D2-D3: count consecutive 401s; flag abort at threshold."""
        if response.status_code == 401:
            self._consecutive_401s += 1
        else:
            self._consecutive_401s = 0
        if (
            self.auth_configured
            and self._consecutive_401s >= _AUTH_LOSS_THRESHOLD
            and not self._aborted
        ):
            self._aborted = True
            self._abort_reason = (
                f"auth expired: {self._consecutive_401s} consecutive "
                f"HTTP 401 responses "
                f"(last url={getattr(response, 'url', '?')})"
            )
        return response

    # ------------------------------------------------------------------

    def register_adapter(self, module: str, fn: ModuleAdapter) -> None:
        self.adapters[module] = fn

    # ------------------------------------------------------------------

    def _fingerprint(self, target: str) -> tuple[list[str], str | None]:
        """Return (platforms, waf). Uses the injected fingerprinter.

        The fingerprinter is expected to return an object with a `.cms`
        attribute (str | None) and optionally a `.waf` attribute.
        """
        if self.fingerprinter is None:
            return [], None

        fp = self.fingerprinter(target)
        platforms: list[str] = []

        cms = getattr(fp, "cms", None)
        if isinstance(cms, str) and cms:
            platforms.append(cms.lower())

        waf = getattr(fp, "waf", None)
        if waf is None:
            waf_name = None
        elif isinstance(waf, str):
            waf_name = waf
        else:
            waf_name = getattr(waf, "vendor", None)

        if self.allowed_platforms is not None:
            platforms = [p for p in platforms if p in self.allowed_platforms]

        # Always consider GraphQL and websocket surfaces as candidates
        # when the caller allowed them and the fingerprinter did not
        # rule them out. The agent does not probe for them itself.
        return platforms, waf_name

    # ------------------------------------------------------------------

    def run(self, target: str, extra_platforms: list[str] | None = None) -> AgentRun:
        result = AgentRun(target=target)
        # Reset abort state from any prior run (ADR-011 D2).
        self._consecutive_401s = 0
        self._aborted = False
        self._abort_reason = ""

        platforms, waf = self._fingerprint(target)
        if extra_platforms:
            for p in extra_platforms:
                pl = (p or "").lower()
                if pl and pl not in platforms:
                    platforms.append(pl)
        result.platforms = platforms
        result.waf = waf

        # Determine the plan.
        plan = plan_for(platforms)
        if not plan:
            # Fall back to a conservative identification-only plan.
            plan = ["scan"] if "scan" in self.adapters else []
        result.plan = plan[: self.max_modules]

        if not result.plan:
            result.aborted = True
            result.abort_reason = (
                "no modules to run: no platforms detected and no "
                "fallback scan adapter registered"
            )
            result.total_findings = self.store.count()
            return result

        # Run each module in order.
        context: dict = {
            "platforms": platforms,
            "waf": waf,
            "target": target,
            "session": self.session,
        }
        for module in result.plan:
            adapter = self.adapters.get(module)
            if adapter is None:
                result.modules_skipped.append(module)
                continue
            try:
                findings = adapter(target, context)
            except Exception as exc:
                result.modules_skipped.append(module)
                context.setdefault("errors", []).append(
                    {"module": module, "error": str(exc)}
                )
                continue
            added = self.store.extend(findings)
            result.new_findings += added
            result.modules_run.append(module)
            if self._aborted:  # ADR-011 D5: break after current module
                result.aborted = True
                result.abort_reason = self._abort_reason
                break

        result.total_findings = self.store.count()
        return result

    # ------------------------------------------------------------------

    @staticmethod
    def known_platforms() -> list[str]:
        return known_platforms()
