"""StackProfile: the output of identify()."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Field:
    """One identified attribute (server, framework, language, waf, cdn)."""

    value: str | None = None
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)


@dataclass
class StackProfile:
    """Fingerprint of the target stack derived from baseline headers."""

    server: Field = field(default_factory=Field)
    framework: Field = field(default_factory=Field)
    language: Field = field(default_factory=Field)
    waf: Field = field(default_factory=Field)
    cdn: Field = field(default_factory=Field)

    def to_dict(self) -> dict:
        return {
            "server": {
                "value": self.server.value,
                "confidence": self.server.confidence,
                "evidence": list(self.server.evidence),
            },
            "framework": {
                "value": self.framework.value,
                "confidence": self.framework.confidence,
                "evidence": list(self.framework.evidence),
            },
            "language": {
                "value": self.language.value,
                "confidence": self.language.confidence,
                "evidence": list(self.language.evidence),
            },
            "waf": {
                "value": self.waf.value,
                "confidence": self.waf.confidence,
                "evidence": list(self.waf.evidence),
            },
            "cdn": {
                "value": self.cdn.value,
                "confidence": self.cdn.confidence,
                "evidence": list(self.cdn.evidence),
            },
        }
