"""SARIF rule catalog for JANISSARY findings.

Maps (category, finding_type) pairs to SARIF 2.1.0 rule descriptors.
Used by ``cli._write_sarif`` to populate
``runs[].tool.driver.rules[]``, to derive per-result ``level`` and
``properties.security-severity``, and to build the CWE taxonomy.

The catalog enumerates every finding_type the scanner emits as a
final finding. Anything unrecognized -- corroborators, future
finding types, agent findings if they ever reach this code path --
falls through to a generic descriptor derived from the finding's own
fields. SARIF output stays valid; display metadata is minimal.

Design constraints (ADR-008):
- Rule IDs are ``{category}:{finding_type}`` -- stable, matches the
  ``ruleId`` that ``_write_sarif`` already emitted before this module.
- ``security-severity`` is a CVSS-style 0.0-10.0 float, mapped from
  severity. GitHub Code Scanning reads this to compute the severity
  badge.
- ``level`` is one of SARIF's four: ``error`` / ``warning`` /
  ``note`` / ``none``. We never emit ``none``.
- CWE tags follow the ``external/cwe/cwe-NNN`` convention that
  GitHub Code Scanning displays as taxonomy links.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SARIF_VERSION = "2.1.0"
TOOL_NAME = "JANISSARY"
TOOL_URI = "https://github.com/Hetaireia/janissary"
CWE_TAXONOMY_URI = "https://cwe.mitre.org/data/definitions/{cwe}.html"

# Severity -> SARIF level (SARIF 2.1.0 3.27.10).
# critical/high are blocking (error); medium is notable (warning);
# low/info are informational (note). Unknown defaults to note so an
# unrecognized severity never masks a result.
_LEVEL_MAP: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# Severity -> GitHub Code Scanning security-severity, aligned with
# GitHub's documented tier boundaries: critical >= 9.0, high >= 7.0,
# medium >= 4.0, low > 0.0.
_SEVERITY_SCORE: dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.5,
    "low": 3.5,
    "info": 0.1,
}


def sarif_level(severity: str) -> str:
    """Map a finding severity to a SARIF result level."""
    return _LEVEL_MAP.get((severity or "").lower(), "note")


def security_severity(severity: str) -> float:
    """Map a finding severity to a CVSS-style 0.0-10.0 score."""
    return _SEVERITY_SCORE.get((severity or "").lower(), 0.1)


def cwe_tag(cwe: int) -> str:
    """Return the SARIF taxonomy tag for a CWE number."""
    return f"external/cwe/cwe-{cwe}"


@dataclass(frozen=True)
class RuleMeta:
    """Metadata for one SARIF rule."""

    category: str
    finding_type: str
    short_description: str
    cwes: tuple[int, ...] = field(default_factory=tuple)
    default_severity: str = "medium"
    help_uri: str = TOOL_URI

    @property
    def rule_id(self) -> str:
        return f"{self.category}:{self.finding_type}"

    def to_sarif(self) -> dict:
        """Return the SARIF rule descriptor for runs[].tool.driver.rules[]."""
        props: dict = {
            "security-severity": f"{security_severity(self.default_severity):.1f}",
        }
        if self.cwes:
            props["tags"] = [cwe_tag(cwe) for cwe in self.cwes]
        return {
            "id": self.rule_id,
            "shortDescription": {"text": self.short_description},
            "helpUri": self.help_uri,
            "properties": props,
        }


# (category, finding_type, short_description, cwes, default_severity)
_SPECS: list[tuple[str, str, str, tuple[int, ...], str]] = [
    # SQL injection
    ("sqli", "db_error", "SQL Injection", (89,), "critical"),
    ("sqli", "sqli_quote_oracle", "SQL Injection (quote oracle)", (89,), "critical"),
    ("sqli", "sql_result_rows", "SQL Injection (result rows)", (89,), "critical"),
    # Path traversal
    (
        "traversal",
        "traversal_collapse",
        "Path Traversal (structural collapse)",
        (22,),
        "critical",
    ),
    (
        "traversal",
        "pathtraver_existence_oracle",
        "Path Traversal (existence oracle)",
        (22,),
        "critical",
    ),
    # Command injection
    ("cmdi", "command_output", "Command Injection", (78,), "critical"),
    ("cmdi", "output_region", "Command Output in Response", (78,), "critical"),
    # LDAP injection
    ("ldapi", "ldap_injection", "LDAP Injection", (90,), "critical"),
    # XPath injection
    ("xpathi", "xpathi_error_oracle", "XPath Injection", (643,), "critical"),
    (
        "xpathi",
        "xpath_result_rows",
        "XPath Injection (result rows)",
        (643,),
        "critical",
    ),
    # XSS
    ("xss", "payload_reflected", "Cross-site Scripting (reflection)", (79,), "high"),
    ("xss", "reflected_xss", "Cross-site Scripting (reflected)", (79,), "high"),
    ("xss", "reflection_context", "Cross-site Scripting (context)", (79,), "high"),
    # Trust boundary
    (
        "trustbound",
        "trustbound_session_oracle",
        "Trust Boundary Violation",
        (501,),
        "high",
    ),
    # Secure cookie
    (
        "securecookie",
        "securecookie_flag_oracle",
        "Sensitive Cookie Missing Secure Flag",
        (614,),
        "medium",
    ),
    # Weak random
    (
        "weakrand",
        "weakrand_rng_oracle",
        "Weak Random Number Generation",
        (338,),
        "high",
    ),
    # SSRF (ADR-012)
    (
        "ssrf",
        "collaborator_hit",
        "Server-Side Request Forgery",
        (918,),
        "critical",
    ),
    (
        "ssrf",
        "dns_only_resolution",
        "Server-Side Request Forgery (DNS-only resolution)",
        (918,),
        "info",
    ),
]

_RULES: dict[tuple[str, str], RuleMeta] = {
    (cat, ft): RuleMeta(
        category=cat,
        finding_type=ft,
        short_description=desc,
        cwes=cwes,
        default_severity=sev,
    )
    for cat, ft, desc, cwes, sev in _SPECS
}


def rule_for(category: str, finding_type: str) -> RuleMeta:
    """Return the RuleMeta for a (category, finding_type) pair.

    Falls back to a generic descriptor when the pair is not cataloged.
    The fallback humanizes the finding_type as the short description
    and defaults to severity tier 'medium' without CWE tags. This
    keeps SARIF output valid for finding types added in future phases
    without requiring a code change here.
    """
    hit = _RULES.get((category, finding_type))
    if hit is not None:
        return hit
    display = (finding_type or "Unknown Finding").replace("_", " ").title()
    return RuleMeta(
        category=category or "unknown",
        finding_type=finding_type or "unknown",
        short_description=display,
        cwes=(),
        default_severity="medium",
    )


def all_rule_ids() -> list[str]:
    """Return every rule ID in the catalog. Test helper."""
    return sorted(meta.rule_id for meta in _RULES.values())


def cwe_taxonomy() -> dict:
    """Return the SARIF taxonomies[] entry for CWE.

    Lists every CWE referenced by the catalog. Over-listing
    (taxonomy entries with no matching results) is valid per SARIF
    2.1.0 3.19.3 and harmless -- dashboards only link what they use.
    """
    cwes: set[int] = set()
    for meta in _RULES.values():
        cwes.update(meta.cwes)
    return {
        "name": "CWE",
        "organization": "MITRE",
        "informationUri": "https://cwe.mitre.org/",
        "taxa": [
            {
                "id": f"cwe-{cwe}",
                "name": f"CWE-{cwe}",
                "shortDescription": {"text": f"CWE-{cwe}"},
                "helpUri": CWE_TAXONOMY_URI.format(cwe=cwe),
            }
            for cwe in sorted(cwes)
        ],
    }
