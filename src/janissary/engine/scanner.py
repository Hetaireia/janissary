"""Minimal HTTP scanner that drives the differential detection engine.

This is the port of the original janissary.run_scan, reduced to the
essential path: baseline collection, payload dispatch, and finding
emission. WAF pacing, POST bodies, and multi-threading are added in
later passes.
"""

from __future__ import annotations

import asyncio
import secrets
import sys
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from janissary.detection import (
    Baseline,
    DifferentialAnalyzer,
    ResponseSnapshot,
    check_ldap_injection_oracle,
    check_pathtraver_oracle,
    check_securecookie_oracle,
    check_sqli_quote_oracle,
    check_trustbound_oracle,
    check_weakrand_oracle,
    check_xpath_error_oracle,
)
from janissary.detection.blind_sqli_oracle import check_blind_sqli_oracle
from janissary.detection.collapse_oracle import check_traversal_collapse_oracle
from janissary.detection.lfi_oracle import check_lfi_content_oracle
from janissary.detection.ssrf_response_oracle import check_ssrf_response_oracle
from janissary.engine.baseline_struct import compute_arming_state
from janissary.finding_identity import compute_fingerprint
from janissary.heuristic.types import Observation
from janissary.integrations.graphql import GraphQLClient, detect
from janissary.integrations.graphql_discovery import GraphQLDiscoveryModule
from janissary.integrations.websocket_discovery import WebSocketDiscoveryModule
from janissary.integrations.websocket_learn import learn
from janissary.output.raw_http import (
    serialize_request,
    serialize_response,
)
from janissary.protocols import BaselineNormalizer, HTTPNormalizer
from janissary.recon import (
    AdaptivePacer,
    PacerConfig,
    WAFDetector,
    WAFProfile,
)
from janissary.verification import (
    AnalyzerImplicitConfirmer,
    CandidateFinding,
    CorroboratorConfirmer,
    GraphQLReconConfirmer,
    VerificationEngine,
    VerifiedFinding,
    WebSocketReconConfirmer,
)
from janissary.verification.confirmers import HeuristicConfirmer, IdorConfirmer

# -------------------------------------------------------------------
# PAYLOAD LIBRARY
# -------------------------------------------------------------------

DEFAULT_PAYLOADS: list[tuple[str, str, str, str]] = [
    ("sql_single_quote", "'", "sqli", "high"),
    ("sql_double_quote", '"', "sqli", "high"),
    ("sql_or_1eq1", "' OR '1'='1", "sqli", "critical"),
    ("sql_union_null", "' UNION SELECT NULL,NULL,NULL--", "sqli", "critical"),
    ("sql_sleep_mysql", "' OR SLEEP(5)--", "sqli", "critical"),
    ("sql_sleep_pg", "'; SELECT pg_sleep(5)--", "sqli", "critical"),
    ("sql_paren_quote", "')", "sqli", "high"),
    ("sql_paren_double", "'))", "sqli", "high"),
    ("sql_paren_union", "')) UNION SELECT NULL,NULL,NULL--", "sqli", "critical"),
    ("sql_paren_or", "')) OR '1'='1", "sqli", "critical"),
    ("sql_hash_comment", "'#", "sqli", "high"),
    ("xpath_or_1eq1", "' or '1'='1", "xpathi", "critical"),
    ("ldap_wildcard", "*", "ldapi", "critical"),
    ("ldap_filter_break", "*)(uid=*))(|(uid=*", "ldapi", "critical"),
    ("xss_script", "<script>alert(1)</script>", "xss", "high"),
    ("xss_img", "<img src=x onerror=alert(1)>", "xss", "high"),
    ("traversal_passwd", "../../../etc/passwd", "traversal", "critical"),
    ("traversal_encoded", "..%2f..%2f..%2fetc%2fpasswd", "traversal", "critical"),
    ("traversal_passwd_deep", "../../../../../etc/passwd", "traversal", "critical"),
    ("traversal_passwd_abs", "/etc/passwd", "traversal", "critical"),
    # ADR-027 D3: broaden traversal payload coverage. Windows file
    # target (win.ini) plus structural variants (double-slash, double-
    # encoded) that exercise different servlet input-filter paths.
    ("traversal_win_ini", "..\\..\\..\\windows\\win.ini", "traversal", "critical"),
    (
        "traversal_win_encoded",
        "..%5c..%5c..%5cwindows%5cwin.ini",
        "traversal",
        "critical",
    ),
    (
        "traversal_passwd_double",
        "....//....//....//etc/passwd",
        "traversal",
        "critical",
    ),
    (
        "traversal_passwd_dot",
        "..%252f..%252f..%252fetc%252fpasswd",
        "traversal",
        "critical",
    ),
    ("ssrf_mailhog_canary", "http://mailhog:8025/", "ssrf", "critical"),
    # Cloud metadata endpoints (ADR-012 D2 follow-up). Best-effort: GCP
    # and Azure require specific headers (Metadata-Flavor: Google,
    # Metadata: true) which the target must forward. AWS IMDSv1 has no
    # header requirement; v6 is the IPv6 variant. Response-body markers
    # in SSRF_BODY_MARKERS match content unique to each provider.
    (
        "ssrf_metadata_aws",
        "http://169.254.169.254/latest/meta-data/",
        "ssrf",
        "critical",
    ),
    (
        "ssrf_metadata_aws_v6",
        "http://[fd00:ec2::254]/latest/meta-data/",
        "ssrf",
        "critical",
    ),
    (
        "ssrf_metadata_gcp",
        "http://metadata.google.internal/computeMetadata/v1/",
        "ssrf",
        "critical",
    ),
    (
        "ssrf_metadata_azure",
        "http://169.254.169.254/metadata/instance",
        "ssrf",
        "critical",
    ),
    ("sqli_blind_true", "1' OR '1'='1", "sqli_blind", "high"),
    ("sqli_blind_false", "1' AND '1'='2", "sqli_blind", "high"),
    ("cmdi_semicolon", "; cat /etc/passwd", "cmdi", "critical"),
    ("cmdi_sleep", "; sleep 5", "cmdi", "critical"),
    # cmdi on Linux without a shell wrapper: Runtime.exec() splits the
    # argument on whitespace and execs the first token, so shell-meta
    # payloads like "; cat /etc/passwd" fail with "Cannot run program ;".
    # These bare-command payloads are valid executables and produce
    # stdout that _check_output_region recognizes.
    ("cmdi_bare_id", "id", "cmdi", "critical"),
    ("cmdi_bare_uname", "uname -a", "cmdi", "critical"),
    ("cmdi_bare_passwd", "cat /etc/passwd", "cmdi", "critical"),
    ("cmdi_bare_whoami", "whoami", "cmdi", "critical"),
    # Env-var sink shape: target execs a fixed shell script that
    # evaluates $FOO. Payload must be the env-entry string "FOO=<cmd>",
    # not a URL-level shell metachar. Discovered on cmdi-00/495-497;
    # see Amendment 15.
    ("cmdi_env_marker", "FOO=echo JNSRY_MARK", "cmdi", "critical"),
    ("cmdi_env_id", "FOO=id", "cmdi", "critical"),
]


# Response-body markers for SSRF payloads that expect content in the
# target's response (not OOB via collaborator). Keyed by payload name;
# value is a list of substrings where any single match triggers emission.
# ADR-012 D2 note: metadata_http/metadata_v6/file were deferred to a
# response-body path; this dict is that path.
SSRF_BODY_MARKERS: dict[str, list[str]] = {
    "ssrf_mailhog_canary": ["MailHog", "mailhog"],
    "ssrf_metadata_aws": [
        "ami-id",
        "ami-launch-index",
        "instance-id",
        "placement/",
    ],
    "ssrf_metadata_aws_v6": [
        "ami-id",
        "ami-launch-index",
        "instance-id",
        "placement/",
    ],
    "ssrf_metadata_gcp": [
        "project/project-id",
        "instance/zone",
        "service-accounts/",
    ],
    "ssrf_metadata_azure": [
        "vmId",
        "subscriptionId",
        "resourceGroupName",
    ],
}

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# -------------------------------------------------------------------
# STDERR LOGGING
# -------------------------------------------------------------------


def _say(*args, **kwargs) -> None:
    """Status prints go to stderr; stdout is reserved for the payload."""
    kwargs["file"] = sys.stderr
    print(*args, **kwargs)


# -------------------------------------------------------------------
# URL BUILDING
# -------------------------------------------------------------------


# Finding types the analyzer emits without any category-specific gate.
# They are corroborators, not detectors: on a target that 500s for any
# unknown input, every payload class produces the same observation, so
# attaching the payload's category would attribute one fact to several
# categories (F-002 through F-007 on /traversal). Dropped as standalone
# findings *when the baseline is noisy or non-2xx*. On a stable 2xx
# baseline a large length delta is real signal and is emitted. See
# WORKFLOW.md, "Structural misattribution".
CORROBORATOR_ONLY_TYPES = frozenset(
    {
        "length_anomaly",
        "length_shrink",
    }
)


def build_url(base: str, param: str, value: str) -> str:
    """Inject `param=value` into the URL, preserving other parameters."""
    parsed = urlparse(base)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [value]
    new_query = urlencode(query, doseq=True)
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        )
    )


def repair_url(url: str) -> str:
    """Collapse spaces around the path/query split."""
    if not url:
        return url
    url = url.strip()
    if "?" in url:
        head, _, tail = url.partition("?")
        return head.replace(" ", "") + "?" + tail
    return url.replace(" ", "")


# -------------------------------------------------------------------
# RESULT TYPES
# -------------------------------------------------------------------


@dataclass
class ScanFinding:
    param: str
    payload_name: str
    payload_value: str
    category: str
    severity: str
    finding_type: str
    detail: str
    response_status: int | None = None
    response_length: int = 0
    response_time: float | None = None
    reflection_context: str | None = None
    response_content_type: str = ""

    # Wire-level artifacts for Burp Repeater paste-in.
    url: str = ""
    method: str = "GET"
    raw_request: str | None = None
    raw_response: str | None = None

    # Stable cross-scan identity (ADR-007). Populated in __post_init__.
    fingerprint: str = ""

    # Phase 0.1: verification metadata. Defaults preserve backwards
    # compatibility - pre-Phase-0.1 emission sites remain 'verified'
    # with no reason. Rewired sites populate both from VerifiedFinding.
    verification_status: str = "verified"
    verification_reason: str | None = None

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = compute_fingerprint(
                target=self.url or "",
                discriminator=self.param or "",
                category=self.category or "",
                finding_type=self.finding_type or "",
            )


def _to_scan_finding(verified: VerifiedFinding) -> ScanFinding:
    """Convert a VerifiedFinding to ScanFinding for emission.

    Fingerprint is computed by ScanFinding.__post_init__ from the same
    fields, so we do not pass it explicitly.
    """
    finding = ScanFinding(
        param=verified.param,
        payload_name=verified.payload_name,
        payload_value=verified.payload_value,
        category=verified.category,
        severity=verified.severity,
        finding_type=verified.finding_type,
        detail=verified.detail,
        response_status=verified.response_status,
        response_length=verified.response_length,
        response_time=verified.response_time,
        reflection_context=verified.reflection_context,
        response_content_type=verified.response_content_type,
        url=verified.url,
        method=verified.method,
        raw_request=verified.raw_request,
        raw_response=verified.raw_response,
        verification_status=verified.verification_status,
        verification_reason=verified.verification_reason,
    )
    finding._engine_emitted = True
    return finding


def _ws_url_from_target(target: str) -> str:
    """Return a WebSocket URL derived from an HTTP(S) target.

    scan_ws calls preflight() (HTTP-only) against self.target, then
    hands the same target to learn() and WebSocketDiscoveryModule,
    both of which call websockets.connect() -- which rejects http(s).
    This seam is the one place that reconciles the two protocols.

    ws:// and wss:// pass through unchanged so that callers already
    on the right scheme are not double-converted.
    """
    if target.startswith("ws://") or target.startswith("wss://"):
        return target
    if target.startswith("https://"):
        return "wss://" + target[len("https://") :]
    if target.startswith("http://"):
        return "ws://" + target[len("http://") :]
    return target


_ENGINE = VerificationEngine(
    confirmers=[
        CorroboratorConfirmer(),
        WebSocketReconConfirmer(),
        GraphQLReconConfirmer(),
        HeuristicConfirmer(),
        IdorConfirmer(),
        AnalyzerImplicitConfirmer(),
    ]
)


class _VerifiedFindingsList(list):
    """A list that asserts every appended item carries _engine_emitted=True.

    Phase 0.1 invariant: ScanSummary.findings contains only findings produced
    by VerificationEngine.verify() -> _to_scan_finding(). Any direct
    ScanFinding(...) construction that bypasses the engine and tries to
    append here raises AssertionError.

    The marker is a non-dataclass attribute set only by _to_scan_finding().
    It is not visible to dataclasses.asdict() (which only walks fields) and
    invisible to consumers that filter underscore-prefixed keys from vars().
    """

    def append(self, item):
        if not getattr(item, "_engine_emitted", False):
            raise AssertionError(
                f"Phase 0.1 invariant violation: ScanSummary.findings.append "
                f"received a finding that did not come from "
                f"VerificationEngine.verify() -> _to_scan_finding(). "
                f"Offender: {item!r}"
            )
        super().append(item)

    def extend(self, items):
        for item in items:
            if not getattr(item, "_engine_emitted", False):
                raise AssertionError(
                    f"Phase 0.1 invariant violation: ScanSummary.findings.extend "
                    f"received a finding that did not come from "
                    f"VerificationEngine.verify() -> _to_scan_finding(). "
                    f"Offender: {item!r}"
                )
        super().extend(items)


@dataclass
class ScanSummary:
    target: str
    params: list[str]
    method: str
    total_requests: int = 0
    finding_count: int = 0
    aborted: bool = False
    abort_reason: str | None = None
    scan_incomplete: bool = False  # True if aborted mid-scan (partial results present)
    baselines: dict = field(default_factory=dict)
    findings: list[ScanFinding] = field(default_factory=_VerifiedFindingsList)
    groups: list = field(default_factory=list)
    waf: dict | None = None
    pacer: dict | None = None


# -------------------------------------------------------------------
# SCANNER
# -------------------------------------------------------------------


def _substitute_placeholder(obj, placeholder, value):
    """Recursively replace placeholder in a template structure. Pure.

    Dict keys starting with underscore are metadata (e.g. _categories)
    and are stripped from the request body before sending.
    """
    if isinstance(obj, str):
        return obj.replace(placeholder, value) if placeholder in obj else obj
    if isinstance(obj, dict):
        return {
            k: _substitute_placeholder(v, placeholder, value)
            for k, v in obj.items()
            if not (isinstance(k, str) and k.startswith("_"))
        }
    if isinstance(obj, list):
        return [_substitute_placeholder(v, placeholder, value) for v in obj]
    return obj


class Scanner:
    """Minimal scanner: baseline, dispatch, analyze."""

    def __init__(
        self,
        target: str,
        params: list[str],
        method: str = "GET",
        timeout: float = 10.0,
        baseline_count: int = 10,
        delay: float = 0.0,
        stealth: bool = False,
        proxies: dict | None = None,
        session: requests.Session | None = None,
        detect_waf: bool = True,
        pacer_config: PacerConfig | None = None,
        inject_in: str = "auto",
        auth_configured: bool = False,
        collaborator: object | None = None,
        ssrf_timeout: float = 10.0,
        json_template: dict | None = None,
        baseline_value: str = "",
        normalizer: BaselineNormalizer | None = None,
        collect_observations: bool = False,
        verbose: bool = False,
        auth_sessions: list | None = None,
    ):
        self.target = repair_url(target)
        self.params = params
        self.method = method.upper()
        self.timeout = timeout
        self.baseline_count = max(3, baseline_count)
        self.delay = delay
        self.stealth = stealth
        self.proxies = proxies
        self.session = session or requests.Session()
        self.auth_configured = auth_configured
        self.collaborator = collaborator
        self.ssrf_timeout = ssrf_timeout
        self.json_template = json_template
        self.normalizer = normalizer if normalizer is not None else HTTPNormalizer()
        self.baseline_value = baseline_value
        self._ssrf_poll_delays: list[float] = [2.0, 3.0, 5.0]
        self._consecutive_401s: int = 0
        self._ua = DEFAULT_USER_AGENT
        self.detect_waf = detect_waf
        self._collect_observations = collect_observations
        self.verbose = verbose
        self._observations: list[Observation] = []
        self._session_rotator = None
        if auth_sessions:
            from janissary.engine.session_rotator import SessionRotator

            self._session_rotator = SessionRotator(auth_sessions)
        self.inject_in = inject_in.lower()
        if self.inject_in not in {
            "auto",
            "query",
            "body",
            "cookie",
            "header",
            "param-name",
            "json-body",
            "path",
        }:
            raise ValueError(f"invalid inject_in: {inject_in!r}")
        if self.inject_in == "json-body" and not self.json_template:
            raise ValueError("inject_in='json-body' requires json_template")
        if self.inject_in == "path":  # noqa: SIM102
            if not any(f"{{{p}}}" in self.target for p in self.params):
                raise ValueError(
                    "inject_in='path' requires a {param} placeholder in URL"
                )

        cfg = pacer_config or PacerConfig(base_delay=delay)
        if cfg.min_delay < delay:
            cfg.min_delay = delay
        self.pacer_config = cfg

        self._traversal_nonce = secrets.token_hex(6)
        self._trustbound_nonce = "JNSRY_TB_" + secrets.token_hex(10)
        self._payloads = [
            *DEFAULT_PAYLOADS,
            ("trustbound_marker", self._trustbound_nonce, "trustbound", "high"),
        ]
        if self.inject_in == "json-body":
            # json-body: filter to categories declared in the template's
            # _categories field. Default ["ssrf"] preserves backward
            # compatibility with pre-7.8 templates (crapi_mechanic.json).
            # The _categories key is stripped from the request body by
            # _substitute_placeholder() before sending.
            _json_cats = ["ssrf"]
            if isinstance(self.json_template, dict):
                _declared = self.json_template.get("_categories")
                if isinstance(_declared, list) and _declared:
                    _json_cats = [str(cc) for cc in _declared]
            self._payloads = [p for p in self._payloads if p[2] in _json_cats]
        self.waf_profile: WAFProfile | None = None
        self._pacer: AdaptivePacer | None = None

    # ---------------------------------------------------------------

    def get_observations(self) -> list[Observation]:
        """Return a defensive copy of collected observations."""
        return list(self._observations)

    def run_heuristic(self) -> list[ScanFinding]:
        """Run heuristic (Track B) engine on collected observations. (M38)

        Per ADR-022 D2: candidates route through _ENGINE.verify() -> _to_scan_finding(),
        same emission path Track A uses. Requires collect_observations=True,
        otherwise returns [] (no observations collected).
        """
        if not self._observations:
            return []
        from janissary.heuristic.engine import HeuristicEngine
        from janissary.verification.types import VerifiedFinding as _VF

        engine = HeuristicEngine()
        matches = engine.match(self._observations)
        candidates = engine.to_candidates(matches, self._observations)
        findings: list[ScanFinding] = []
        for c in candidates:
            result = _ENGINE.verify(c)
            if isinstance(result, _VF):
                findings.append(_to_scan_finding(result))
        return findings

    def _headers(self) -> dict:
        headers = {
            "User-Agent": self._ua,
            "Accept": "text/html,application/json,*/*;q=0.8",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        if self.stealth:
            headers["X-Forwarded-For"] = "127.0.0.1"
        return headers

    def _request(
        self, url: str, param: str, value: str, allow_redirects: bool = False
    ) -> requests.Response | None:
        if self.inject_in == "param-name":
            # OWASP Benchmark "getParameterNames" cases: the payload is
            # delivered as the parameter *name*, whose value is the
            # testname. Over POST send it in the form body; over GET
            # append it as a query pair.
            if self.method == "POST":
                return self.session.post(
                    self.target,
                    headers=self._headers(),
                    data={value: param},
                    timeout=self.timeout,
                    allow_redirects=allow_redirects,
                    proxies=self.proxies,
                )
            return self.session.get(
                build_url(self.target, value, param),
                headers=self._headers(),
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                proxies=self.proxies,
            )

        if self.inject_in == "header":
            hdrs = self._headers()
            hdrs[param] = value
            kwargs = {
                "headers": hdrs,
                "timeout": self.timeout,
                "allow_redirects": allow_redirects,
                "proxies": self.proxies,
            }
            if self.method == "POST":
                return self.session.post(self.target, **kwargs)
            return self.session.get(self.target, **kwargs)

        if self.inject_in == "cookie":
            kwargs = {
                "headers": self._headers(),
                "cookies": {param: value},
                "timeout": self.timeout,
                "allow_redirects": allow_redirects,
                "proxies": self.proxies,
            }
            if self.method == "POST":
                return self.session.post(self.target, **kwargs)
            return self.session.get(self.target, **kwargs)

        if self.inject_in == "json-body":
            if not self.json_template:
                raise ValueError("inject_in='json-body' requires json_template")
            body = _substitute_placeholder(self.json_template, "{{PAYLOAD}}", value)
            return self.session.post(
                self.target,
                json=body,
                headers=self._headers(),
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                proxies=self.proxies,
            )

        if self.inject_in == "path":
            from urllib.parse import quote as _quote

            path_url = url.replace(f"{{{param}}}", _quote(value, safe=""))
            kwargs = {
                "headers": self._headers(),
                "timeout": self.timeout,
                "allow_redirects": allow_redirects,
                "proxies": self.proxies,
            }
            if self.method == "POST":
                return self.session.post(path_url, **kwargs)
            return self.session.get(path_url, **kwargs)

        if self.inject_in == "body" or (
            self.inject_in == "auto" and self.method == "POST"
        ):
            # Amendment 7: dual-vector. Send the payload in the query
            # string as well as the form body. Servlets reading
            # getParameter() see the body; servlets reading
            # getQueryString() see the query. Previously the body
            # path sent only the body, and getQueryString() servlets
            # were unreachable.
            return self.session.post(
                build_url(self.target, param, value),
                headers=self._headers(),
                data={param: value},
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                proxies=self.proxies,
            )
        return self.session.get(
            build_url(url, param, value),
            headers=self._headers(),
            timeout=self.timeout,
            allow_redirects=allow_redirects,
            proxies=self.proxies,
        )

    def _paced_request(
        self, url: str, param: str, value: str
    ) -> requests.Response | None:
        """Request through the adaptive pacer."""
        if self._pacer is not None:
            self._pacer.wait()
        start = time.perf_counter()
        try:
            r = self._request(url, param, value)
        except requests.RequestException:
            if self._pacer is not None:
                self._pacer.record(None, time.perf_counter() - start)
            raise
        if self._pacer is not None:
            self._pacer.record(r.status_code, time.perf_counter() - start)
        return r

    # ---------------------------------------------------------------

    def preflight(self) -> tuple[bool, str]:
        """One request to confirm the endpoint responds.

        Uses the configured injection vector with a benign value so
        that targets which require a cookie/header to reach the sink
        are not rejected before scanning begins.
        """
        param = self.params[0] if self.params else "q"
        try:
            r = self._request(self.target, param, "1", allow_redirects=True)
        except requests.RequestException as e:
            return False, f"request error: {e}"
        if r is None:
            return False, "no response"
        if r.status_code >= 500:
            return False, f"server error: HTTP {r.status_code}"
        if not (r.text or "").strip():
            return False, "empty body"
        return True, ""

    # ---------------------------------------------------------------

    def _detect_waf(self, quiet: bool = False) -> WAFProfile:
        detector = WAFDetector(
            session=self.session,
            timeout=self.timeout,
            proxies=self.proxies,
            param=self.params[0] if self.params else "q",
            user_agent=self._ua,
        )
        if not quiet:
            _say("[*] Probing for WAF...")
        profile = detector.detect(self.target)
        if not quiet:
            if profile.detected:
                vendor = profile.vendor or "unknown"
                _say(
                    f"    WAF detected: {vendor} (confidence {profile.confidence:.2f})"
                )
            else:
                _say("    No WAF signatures observed")
        return profile

    # ---------------------------------------------------------------

    def collect_baseline(self, param: str) -> Baseline:
        """Sample the target N times using a single known-good value.

        The baseline must measure the app's response to *identical* input.
        If the user pointed us at a URL that already carries a value for
        this parameter (e.g. ?f=readme.txt), that value is the known-good
        one and we replay it. Otherwise we fall back to a fixed literal.

        Rotating through different benign values makes `is_stable_body` a
        test of the payload list rather than the target, and on endpoints
        that 500 for unknown input it makes `modal_status` 500 -- silently
        disabling the status and length gates before any payload is sent.
        """
        baseline = Baseline()
        parsed = urlparse(self.target)
        if self.inject_in == "path" and self.baseline_value:
            value = self.baseline_value
        else:
            existing = parse_qs(parsed.query, keep_blank_values=True).get(param)
            value = existing[0] if existing else "1"
        for _ in range(self.baseline_count):
            try:
                r = self._paced_request(self.target, param, value)
            except requests.RequestException:
                continue
            if r is None:
                continue
            baseline.add(ResponseSnapshot.from_response(r, normalizer=self.normalizer))
        return baseline

    def _ssrf_phase(
        self,
        param: str,
        summary: ScanSummary,
        quiet: bool = False,
    ) -> None:
        """ADR-012 D3: send SSRF payloads, poll collaborator, emit findings.

        Called once per param after the differential payload loop. Polls
        at each delay in self._ssrf_poll_delays (default 2s/3s/5s after
        last send). Emits one ScanFinding per matching hit. On
        collaborator unreachable, logs and continues.
        """
        if self.collaborator is None:
            return

        from janissary.integrations.collaborator import (
            SSRF_PAYLOADS,
            CollaboratorError,
        )

        issued: list[tuple[str, str, str, object]] = []
        for payload in SSRF_PAYLOADS:
            uniq = self.collaborator.new_unique_id(payload.name)
            url = self.collaborator.payload_for(payload, uniq)
            try:
                r = self._paced_request(self.target, param, url)
            except requests.RequestException:
                r = None
            summary.total_requests += 1
            issued.append((uniq, payload.name, url, r))

        if not issued:
            return

        pending = list(issued)
        for delay in self._ssrf_poll_delays:
            time.sleep(delay)
            still_pending: list[tuple[str, str, str, object]] = []
            for uniq, payload_name, url, r in pending:
                try:
                    hits = self.collaborator.poll(uniq)
                except CollaboratorError:
                    continue
                if not hits:
                    still_pending.append((uniq, payload_name, url, r))
                    continue
                for hit in hits:
                    proto = (hit.protocol or "").lower()
                    if proto in ("http", "https"):
                        sev = "critical"
                        ftype = "collaborator_hit"
                        detail = (
                            f"OOB hit: {proto} from "
                            f"{hit.source_ip or '?'} at "
                            f"{hit.timestamp or '?'} via {payload_name} "
                            f"on param {param}"
                        )
                    elif proto == "dns":
                        sev = "info"
                        ftype = "dns_only_resolution"
                        detail = (
                            f"OOB DNS-only hit (no HTTP fetch): "
                            f"{hit.source_ip or '?'} via {payload_name} "
                            f"on param {param}"
                        )
                    else:
                        continue

                    req_obj = getattr(r, "request", None) if r is not None else None
                    candidate = CandidateFinding(
                        param=param,
                        payload_name=payload_name,
                        payload_value=url,
                        category="ssrf",
                        severity=sev,
                        finding_type=ftype,
                        detail=detail,
                        response_status=(r.status_code if r is not None else None),
                        response_length=(len(r.text or "") if r is not None else 0),
                        response_content_type=(
                            (r.headers or {}).get("content-type", "")
                            if r is not None
                            else ""
                        ),
                        url=(getattr(req_obj, "url", None) or self.target),
                        method=self.method,
                        raw_request=(
                            serialize_request(req_obj) if req_obj is not None else None
                        ),
                        raw_response=(serialize_response(r) if r is not None else None),
                    )
                    result = _ENGINE.verify(candidate)
                    if not isinstance(result, VerifiedFinding):
                        continue
                    finding = _to_scan_finding(result)
                    summary.findings.append(finding)
                    summary.finding_count += 1
                    if not quiet:
                        _say(f"  [{param}] SSRF {sev.upper()}: {ftype} | {detail[:80]}")
            pending = still_pending
            if not pending:
                break

    def scan_ws(self, payloads: list[str] | None = None) -> ScanSummary:
        """Run WebSocket discovery against ``self.target``.

        Flow: learn() -> WebSocketDiscoveryModule.discover() -> _ENGINE verify.
        Every candidate is routed through _ENGINE.verify() so the
        WebSocketReconConfirmer marks it unproven. Same emission
        boundary HTTP and GraphQL findings go through.

        Caller MUST provide payloads. Empty payloads yields a summary
        with ``scan_incomplete=True`` and reason
        "no WS payloads provided" -- not a silent clean result. See
        LIMITATIONS.md "What no finding means".

        If learn() finds no injectable fields (e.g. target sends only
        text frames, or no server response), ``scan_incomplete=True``
        with the reason from learn()'s notes. Not a silent clean.

        This method does not run the HTTP payload loop. Callers wanting
        both HTTP and WS findings should invoke scan() and scan_ws()
        separately and merge them (see CLI --ws in FN-16 part 6).

        See docs/PHASE-6-PLAN.md FN-16.
        """
        summary = ScanSummary(
            target=self.target,
            params=list(self.params),
            method="WS",
        )

        if not payloads:
            summary.scan_incomplete = True
            summary.abort_reason = "no WS payloads provided"
            return summary

        ok, reason = self.preflight()
        summary.total_requests += 1
        if not ok:
            summary.aborted = True
            summary.abort_reason = reason
            return summary

        ws_target = _ws_url_from_target(self.target)
        try:
            model = asyncio.run(
                learn(ws_target, payloads=payloads, timeout=self.timeout)
            )
        except Exception as exc:
            summary.scan_incomplete = True
            summary.abort_reason = f"learn failed: {type(exc).__name__}"
            return summary
        summary.total_requests += len(payloads) + 2

        joined_notes = " ".join(model.notes)
        if "no_probe_payloads_provided" in joined_notes:
            summary.scan_incomplete = True
            summary.abort_reason = "no WS payloads provided"
            return summary
        if "connect_failed" in joined_notes:
            summary.scan_incomplete = True
            summary.abort_reason = "WS connect failed during learn"
            return summary
        if not model.injectable_fields:
            summary.scan_incomplete = True
            summary.abort_reason = (
                "no injectable fields in learned model (notes: "
                + (joined_notes or "none")
                + ")"
            )
            return summary

        module = WebSocketDiscoveryModule(
            url=ws_target, model=model, timeout=self.timeout
        )
        try:
            candidates = asyncio.run(module.discover(max_probes=50))
        except Exception as exc:
            summary.scan_incomplete = True
            summary.abort_reason = f"discover failed: {type(exc).__name__}"
            return summary
        summary.total_requests += max(len(candidates) * 2, 10)

        for candidate in candidates:
            result = _ENGINE.verify(candidate)
            if not isinstance(result, VerifiedFinding):
                continue
            finding = _to_scan_finding(result)
            summary.findings.append(finding)
            summary.finding_count += 1

        return summary

    def _candidate_to_scan_finding(self, c) -> ScanFinding:
        """Convert a CandidateFinding from an integration module to ScanFinding.

        Sets the Phase 0.1 _engine_emitted attribute so the finding can be
        appended to ScanSummary.findings (the asserting list at
        scanner.py:290 checks it on append/extend).
        """
        f = ScanFinding(
            param=c.param,
            payload_name=c.payload_name,
            payload_value=c.payload_value,
            category=c.category,
            severity=c.severity,
            finding_type=c.finding_type,
            detail=c.detail,
            response_status=c.response_status,
            response_length=c.response_length,
            url=getattr(c, "url", ""),
            method=getattr(c, "method", "GET"),
        )
        f._engine_emitted = True
        return f

    def scan_host_bypass(self, baseline_host: str | None = None) -> ScanSummary:
        """Run Host-header ACL bypass detection against self.target.

        See docs/PHASE-6-PLAN.md FN-20 for detection logic and
        verification criteria.
        """
        from janissary.integrations.host_bypass import test_host_bypass

        summary = ScanSummary(
            target=self.target,
            params=["Host"],
            method="HOST-BYPASS",
        )
        try:
            candidates = test_host_bypass(
                self.target,
                baseline_host=baseline_host,
                timeout=self.timeout,
            )
        except Exception as exc:
            summary.scan_incomplete = True
            summary.abort_reason = f"host-bypass failed: {type(exc).__name__}"
            return summary

        # Nominal request count: 1 baseline + up to 2 variants.
        summary.total_requests = 3

        for c in candidates:
            f = self._candidate_to_scan_finding(c)
            summary.findings.append(f)
            summary.finding_count += 1

        return summary

    def scan_graphql(
        self,
        include_probes: bool = True,
        include_fuzz: bool = False,
        max_fuzz_targets: int | None = 20,
    ) -> ScanSummary:
        """Run GraphQL discovery against ``self.target``.

        Returns a ScanSummary whose findings have been routed through
        ``_ENGINE.verify()`` -- so ``GraphQLReconConfirmer`` marks them
        ``unproven`` (recon observations are signals, not vulnerability
        proofs). Same emission boundary HTTP findings go through.

        This method does not run the HTTP payload loop. It is GraphQL
        discovery only. Callers wanting both HTTP and GraphQL findings
        should invoke ``scan()`` and ``scan_graphql()`` separately and
        merge them (see CLI --graphql in part 3c).

        Fuzzing is opt-in: one HTTP request per payload per schema
        target. ``max_fuzz_targets`` caps the number of (field, arg)
        pairs fuzzed (default 20 is a safety valve).

        See docs/PHASE-6-PLAN.md FN-15 part 3b.
        """
        summary = ScanSummary(
            target=self.target,
            params=list(self.params),
            method="POST",  # GraphQLClient is POST-only
        )

        ok, reason = self.preflight()
        summary.total_requests += 1
        if not ok:
            summary.aborted = True
            summary.abort_reason = reason
            return summary

        client = GraphQLClient(
            endpoint=self.target,
            timeout=self.timeout,
            proxies=self.proxies,
            session=self.session,
        )

        profile = detect(self.target, client=client)
        # Approximate request count -- GraphQLDiscoveryModule does not
        # instrument its own HTTP calls. These estimates keep
        # summary.total_requests from being misleadingly zero.
        summary.total_requests += 4  # detect: typename/introspection/batch/suggestions

        if not profile.reachable:
            summary.scan_incomplete = True
            summary.abort_reason = "GraphQL endpoint not reachable"
            return summary

        module = GraphQLDiscoveryModule(client, profile)
        candidates = module.discover(
            include_probes=include_probes,
            include_fuzz=include_fuzz,
            max_fuzz_targets=max_fuzz_targets,
        )

        if include_probes:
            summary.total_requests += 6  # depth_probe + alias_probe, rough

        for candidate in candidates:
            result = _ENGINE.verify(candidate)
            if not isinstance(result, VerifiedFinding):
                continue
            finding = _to_scan_finding(result)
            summary.findings.append(finding)
            summary.finding_count += 1

        return summary

    def _try_rotate_on_401(self, r, param, value, summary):
        """Rotate session on 401 and retry once (ADR-023 D6).

        Returns the (possibly updated) response. If no rotator is
        active, returns r unchanged. If rotation is available but
        retry still fails, returns the retry response (or the
        original r if retry raised) so the ADR-010 counter sees
        the failure.
        """
        if r.status_code != 401 or self._session_rotator is None:
            return r
        if not self._session_rotator.can_rotate():
            return r
        new_spec = self._session_rotator.rotate()
        if new_spec is None:
            return r
        from janissary.auth import AuthConfig, apply_to_session

        apply_to_session(
            self.session,
            AuthConfig(cookie=new_spec.cookie, bearer=new_spec.bearer),
        )
        try:
            retry = self._paced_request(self.target, param, value)
            summary.total_requests += 1
        except requests.RequestException:
            return r
        if retry is not None:
            return retry
        return r

    def run_idor(self, alt_session_spec) -> list[ScanFinding]:
        """Cross-identity IDOR probe (M42, ADR-024 D4-D7).

        Iterates self._observations (requires collect_observations=True),
        refetches each ID-like URL under alt_session_spec (identity B),
        compares to identity A's observation. Returns ScanFinding list
        with verification_status="unproven" via IdorConfirmer.

        Returns [] if observations are empty or alt_session_spec is None.
        """
        if not self._observations or alt_session_spec is None:
            return []
        from janissary.auth import AuthConfig as _AC
        from janissary.auth import apply_to_session
        from janissary.detection.idor import is_idor_candidate, is_idor_testable_url
        from janissary.verification.types import (
            CandidateFinding as _CF,
        )
        from janissary.verification.types import (
            VerifiedFinding as _VF,
        )

        b_session = requests.Session()
        apply_to_session(
            b_session,
            _AC(cookie=alt_session_spec.cookie, bearer=alt_session_spec.bearer),
        )
        if self.proxies:
            b_session.proxies.update(self.proxies)

        findings: list[ScanFinding] = []
        seen: set[str] = set()
        try:
            for obs in self._observations:
                url = obs.url
                if not url or url in seen:
                    continue
                seen.add(url)
                if not is_idor_testable_url(url):
                    continue
                try:
                    b_response = b_session.get(url, timeout=self.timeout)
                except requests.RequestException:
                    continue
                if not is_idor_candidate(
                    obs, b_response.status_code, b_response.text or ""
                ):
                    continue
                candidate = _CF(
                    param=obs.param or "",
                    payload_name="idor",
                    payload_value=url,
                    category="idor",
                    severity="medium",
                    finding_type="idor_candidate",
                    detail=(
                        f"A and B both received "
                        f"{obs.response_status}/{b_response.status_code} "
                        f"with similar body on {url}"
                    ),
                    response_status=b_response.status_code,
                    response_length=len(b_response.text or ""),
                    response_content_type=b_response.headers.get("content-type", ""),
                    url=url,
                    method=obs.method or "GET",
                    discovery_reason="idor:cross_identity_match",
                )
                result = _ENGINE.verify(candidate)
                if isinstance(result, _VF):
                    findings.append(_to_scan_finding(result))
        finally:
            b_session.close()
        return findings

    def scan(self, quiet: bool = False) -> ScanSummary:
        summary = ScanSummary(
            target=self.target,
            params=self.params,
            method=self.method,
        )

        ok, reason = self.preflight()
        summary.total_requests += 1
        if not ok:
            summary.aborted = True
            summary.abort_reason = reason
            return summary

        # WAF detection runs before any payload is sent.
        if self.detect_waf:
            self.waf_profile = self._detect_waf(quiet=quiet)
            summary.total_requests += len(self.waf_profile.probes)
        else:
            self.waf_profile = WAFProfile()

        # Build the pacer now that we know whether a WAF is in play.
        self._pacer = AdaptivePacer(
            config=self.pacer_config,
            waf_profile=self.waf_profile,
        )
        if not quiet and self._pacer.delay > 0:
            _say(f"[*] Initial inter-request delay: {self._pacer.delay:.2f}s")

        for param in self.params:
            baseline = self.collect_baseline(param)
            traversal_snap = None
            traversal_snap_payload = None
            sqli_quote_snap = None
            sqli_or_snap = None
            sqli_quote_resp = None
            weakrand_seen = False
            summary.total_requests += self.baseline_count
            summary.baselines[param] = {
                "samples": len(baseline.snapshots),
                "mean_elapsed": round(baseline.mean_elapsed, 4),
                "std_elapsed": round(baseline.std_elapsed, 4),
                "stable_body": baseline.is_stable_body,
                "has_oracle": baseline.has_oracle,
            }

            arming = compute_arming_state(baseline)
            summary.baselines[param]["arming"] = {
                "armed": arming.armed,
                "reason": arming.reason.value,
                "sample_count": arming.sample_count,
                "hamming_max": arming.hamming_max,
                "has_root_signature": arming.root_signature is not None,
                "emitted_count": 0,
                "emitted_by_reason": {},
            }

            if baseline.is_static and not quiet:
                _say(f"  [{param}] baseline is static - timing gates disabled")

            if baseline.modal_status >= 400 and not quiet:
                _say(
                    f"  [{param}] warning: baseline modal status is "
                    f"{baseline.modal_status} - status gate disabled"
                )

            ldap_wild_snap = None
            sqli_blind_true_snap = None
            sqli_blind_true_status = 0
            sqli_blind_true_payload = ""
            ldap_wild_resp = None
            for name, value, category, _severity in self._payloads:
                try:
                    r = self._paced_request(self.target, param, value)
                except requests.RequestException as e:
                    if not quiet:
                        _say(f"  [{param}] {name} - error: {e}")
                    continue
                summary.total_requests += 1
                if r is None:
                    continue

                # ADR-010 + ADR-023: detect mid-scan auth expiry. When tri-session
                # rotation is active, rotate on 401 and retry once before counting
                # the 401. Single-session behaviour is byte-for-byte ADR-010.
                r = self._try_rotate_on_401(r, param, value, summary)
                if r.status_code == 401:
                    self._consecutive_401s += 1
                else:
                    self._consecutive_401s = 0
                if self.auth_configured and self._consecutive_401s >= 2:
                    summary.aborted = True
                    summary.scan_incomplete = True
                    if self._session_rotator is not None:
                        summary.abort_reason = (
                            f"auth expired: {self._consecutive_401s} "
                            f"consecutive HTTP 401 responses after rotation; "
                            f"{self._session_rotator.attempted_count}/"
                            f"{self._session_rotator.total} sessions attempted "
                            f"(param={param}, last payload={name})"
                        )
                    else:
                        summary.abort_reason = (
                            f"auth expired: {self._consecutive_401s} "
                            f"consecutive HTTP 401 responses "
                            f"(param={param}, last payload={name})"
                        )
                    break

                snapshot = ResponseSnapshot.from_response(r, normalizer=self.normalizer)

                if self._collect_observations and len(self._observations) < 1000:
                    self._observations.append(
                        Observation(
                            url=(
                                getattr(getattr(r, "request", None), "url", None)
                                or self.target
                            ),
                            body=(r.text or ""),
                            headers=dict(r.headers or {}),
                            method=self.method,
                            response_status=r.status_code,
                            payload_name=name,
                            payload_value=value,
                            param=param,
                        )
                    )

                # Collapse oracle (ADR-006, Phase 1.3d): fires when a
                # payload response structurally collapses from the armed
                # baseline AND an auxiliary signal corroborates. D5
                # pass-through: no-op when arming.armed is False.
                if (
                    arming.armed and category == "traversal"
                ):  # ADR-006 D1: only traversal payloads reach the collapse oracle; non-traversal payloads are handled by their own oracle
                    collapse_raw = check_traversal_collapse_oracle(
                        baseline=baseline,
                        arming=arming,
                        snapshot=snapshot,
                        response_status=r.status_code,
                        payload_value=value,
                        payload_name=name,
                    )
                    for cf in collapse_raw:
                        col_req = getattr(r, "request", None)
                        candidate = CandidateFinding(
                            param=param,
                            payload_name=name,
                            payload_value=value,
                            category=cf["category"],
                            severity=cf["severity"],
                            finding_type=cf["type"],
                            detail=cf["detail"],
                            response_status=r.status_code,
                            response_length=len(r.text or ""),
                            response_time=snapshot.elapsed,
                            response_content_type=snapshot.content_type,
                            url=getattr(col_req, "url", None) or self.target,
                            method=self.method,
                            raw_request=serialize_request(col_req),
                            raw_response=serialize_response(r),
                        )
                        result = _ENGINE.verify(candidate)
                        if not isinstance(result, VerifiedFinding):
                            continue
                        col_finding = _to_scan_finding(result)
                        summary.findings.append(col_finding)
                        summary.finding_count += 1
                        tag = cf["reason"] or "collapse_unknown"
                        by = summary.baselines[param]["arming"]["emitted_by_reason"]
                        by[tag] = by.get(tag, 0) + 1
                        summary.baselines[param]["arming"]["emitted_count"] += 1
                        if not quiet:
                            _say(
                                f"  [{param}] {name} -> traversal_collapse "
                                f"| {cf['detail'][:80]}"
                            )

                    # LFI content-injection oracle (Phase 4, FN-2/FN-3).
                    # Complements collapse oracle: collapse catches when
                    # traversal *removes* page structure. This catches
                    # in-page LFI where the page keeps its structure and
                    # file contents appear inside an element (bWAPP
                    # /directory_traversal_1.php, DVWA /vulnerabilities/fi/).
                    # Fires at most once per payload; requires the
                    # signature to be absent from every baseline snapshot.
                    lfi_raw = check_lfi_content_oracle(
                        baseline=baseline,
                        snapshot=snapshot,
                        response_status=r.status_code,
                        payload_value=value,
                        payload_name=name,
                    )
                    for lf in lfi_raw:
                        lfi_req = getattr(r, "request", None)
                        candidate = CandidateFinding(
                            param=param,
                            payload_name=name,
                            payload_value=value,
                            category=lf["category"],
                            severity=lf["severity"],
                            finding_type=lf["type"],
                            detail=lf["detail"],
                            response_status=r.status_code,
                            response_length=len(r.text or ""),
                            response_time=snapshot.elapsed,
                            response_content_type=snapshot.content_type,
                            url=getattr(lfi_req, "url", None) or self.target,
                            method=self.method,
                            raw_request=serialize_request(lfi_req),
                            raw_response=serialize_response(r),
                        )
                        result = _ENGINE.verify(candidate)
                        if not isinstance(result, VerifiedFinding):
                            continue
                        lfi_finding = _to_scan_finding(result)
                        summary.findings.append(lfi_finding)
                        summary.finding_count += 1
                        if not quiet:
                            _say(
                                f"  [{param}] {name} -> lfi_content "
                                f"| {lf['detail'][:80]}"
                            )

                # SSRF response-body oracle (Phase 4, Session B).
                if name.startswith("ssrf_"):
                    _ssrf_markers = SSRF_BODY_MARKERS.get(name, [])
                    if _ssrf_markers:
                        ssrf_raw = check_ssrf_response_oracle(
                            baseline=baseline,
                            snapshot=snapshot,
                            response_status=r.status_code,
                            payload_value=value,
                            payload_name=name,
                            fetch_markers=_ssrf_markers,
                        )
                        for sf in ssrf_raw:
                            ssrf_req = getattr(r, "request", None)
                            candidate = CandidateFinding(
                                param=param,
                                payload_name=name,
                                payload_value=value,
                                category=sf["category"],
                                severity=sf["severity"],
                                finding_type=sf["type"],
                                detail=sf["detail"],
                                response_status=r.status_code,
                                response_length=len(r.text or ""),
                                response_time=snapshot.elapsed,
                                response_content_type=snapshot.content_type,
                                url=getattr(ssrf_req, "url", None) or self.target,
                                method=self.method,
                                raw_request=serialize_request(ssrf_req),
                                raw_response=serialize_response(r),
                            )
                            result = _ENGINE.verify(candidate)
                            if not isinstance(result, VerifiedFinding):
                                continue
                            ssrf_finding = _to_scan_finding(result)
                            summary.findings.append(ssrf_finding)
                            summary.finding_count += 1
                            if not quiet:
                                _say(
                                    f"  [{param}] {name} -> ssrf_response | {sf['detail'][:80]}"
                                )

                # Blind SQLi paired oracle (Phase 4, FN-1).
                if (
                    (arming.armed or self.inject_in == "json-body")
                    and name == "sqli_blind_false"
                    and sqli_blind_true_snap is not None
                ):
                    blind_raw = check_blind_sqli_oracle(
                        true_snapshot=sqli_blind_true_snap,
                        true_status=sqli_blind_true_status,
                        true_payload=sqli_blind_true_payload,
                        false_snapshot=snapshot,
                        false_status=r.status_code,
                        false_payload=value,
                        param=param,
                    )
                    for bl in blind_raw:
                        blind_req = getattr(r, "request", None)
                        candidate = CandidateFinding(
                            param=param,
                            payload_name=name,
                            payload_value=value,
                            category=bl["category"],
                            severity=bl["severity"],
                            finding_type=bl["type"],
                            detail=bl["detail"],
                            response_status=r.status_code,
                            response_length=len(r.text or ""),
                            response_time=snapshot.elapsed,
                            response_content_type=snapshot.content_type,
                            url=getattr(blind_req, "url", None) or self.target,
                            method=self.method,
                            raw_request=serialize_request(blind_req),
                            raw_response=serialize_response(r),
                        )
                        result = _ENGINE.verify(candidate)
                        if not isinstance(result, VerifiedFinding):
                            continue
                        blind_finding = _to_scan_finding(result)
                        summary.findings.append(blind_finding)
                        summary.finding_count += 1
                        if not quiet:
                            _say(
                                f"  [{param}] {name} -> blind_sqli "
                                f"| {bl['detail'][:80]}"
                            )

                # Trustbound session-sink oracle: per-scan high-entropy
                # marker payload; fires only when the marker is echoed
                # into the "saved in session" sink.
                if name == "trustbound_marker":
                    tb_findings = check_trustbound_oracle(baseline, snapshot, value)
                    for f in tb_findings:
                        tb_req = getattr(r, "request", None)
                        candidate = CandidateFinding(
                            param=param,
                            payload_name="trustbound_marker",
                            payload_value=value,
                            category="trustbound",
                            severity=f.get("severity", "high"),
                            finding_type=f.get("type", "trustbound_session_oracle"),
                            detail=f.get("detail", ""),
                            response_status=r.status_code,
                            response_length=len(r.text or ""),
                            response_time=snapshot.elapsed,
                            response_content_type=snapshot.content_type,
                            url=getattr(tb_req, "url", None) or self.target,
                            method=self.method,
                            raw_request=serialize_request(tb_req),
                            raw_response=serialize_response(r),
                        )
                        result = _ENGINE.verify(candidate)
                        if not isinstance(result, VerifiedFinding):
                            continue
                        tb_finding = _to_scan_finding(result)
                        summary.findings.append(tb_finding)
                        summary.finding_count += 1
                        if not quiet:
                            _say(
                                f"  [{param}] {tb_finding.payload_name} -> "
                                f"{tb_finding.severity.upper()}: "
                                f"{tb_finding.finding_type} "
                                f"| {tb_finding.detail[:80]}"
                            )

                    # Securecookie Set-Cookie oracle: same marker
                    # payload, checks whether the reflected cookie
                    # lacks the Secure attribute. Reuses the trustbound
                    # response -- no additional request issued.
                    sc_findings = check_securecookie_oracle(baseline, r, value)
                    for f in sc_findings:
                        sc_req = getattr(r, "request", None)
                        candidate = CandidateFinding(
                            param=param,
                            payload_name="securecookie_flag_oracle",
                            payload_value=value,
                            category="securecookie",
                            severity=f.get("severity", "medium"),
                            finding_type=f.get("type", "securecookie_flag_oracle"),
                            detail=f.get("detail", ""),
                            response_status=r.status_code,
                            response_length=len(r.text or ""),
                            response_time=snapshot.elapsed,
                            response_content_type=snapshot.content_type,
                            url=getattr(sc_req, "url", None) or self.target,
                            method=self.method,
                            raw_request=serialize_request(sc_req),
                            raw_response=serialize_response(r),
                        )
                        result = _ENGINE.verify(candidate)
                        if not isinstance(result, VerifiedFinding):
                            continue
                        sc_finding = _to_scan_finding(result)
                        summary.findings.append(sc_finding)
                        summary.finding_count += 1
                        if not quiet:
                            _say(
                                f"  [{param}] {sc_finding.payload_name} -> "
                                f"{sc_finding.severity.upper()}: "
                                f"{sc_finding.finding_type} "
                                f"| {sc_finding.detail[:80]}"
                            )

                # Weakrand RNG-class oracle: single-response body
                # signature. Checked on every payload response; fires
                # at most once per parameter.
                if not weakrand_seen:
                    wr_findings = check_weakrand_oracle(baseline, snapshot)
                    for f in wr_findings:
                        wr_req = getattr(r, "request", None)
                        candidate = CandidateFinding(
                            param=param,
                            payload_name="weakrand_rng_oracle",
                            payload_value=value,
                            category="weakrand",
                            severity=f.get("severity", "high"),
                            finding_type=f.get("type", "weakrand_rng_oracle"),
                            detail=f.get("detail", ""),
                            response_status=r.status_code,
                            response_length=len(r.text or ""),
                            response_time=snapshot.elapsed,
                            response_content_type=snapshot.content_type,
                            url=getattr(wr_req, "url", None) or self.target,
                            method=self.method,
                            raw_request=serialize_request(wr_req),
                            raw_response=serialize_response(r),
                        )
                        result = _ENGINE.verify(candidate)
                        if not isinstance(result, VerifiedFinding):
                            continue
                        wr_finding = _to_scan_finding(result)
                        summary.findings.append(wr_finding)
                        summary.finding_count += 1
                        if not quiet:
                            _say(
                                f"  [{param}] {wr_finding.payload_name} -> "
                                f"{wr_finding.severity.upper()}: "
                                f"{wr_finding.finding_type} "
                                f"| {wr_finding.detail[:80]}"
                            )
                    if wr_findings:
                        weakrand_seen = True

                # ADR-027 D4: capture first 2xx traversal response for existence
                # oracle, and record which payload produced it. The noexist probe
                # is derived from this payload, not hardcoded /etc/passwd.
                # ADR-027 D4 (reverted 2026-11-05 per D7 verification):
                # capture only from traversal_passwd, as in baseline. Capture broadening
                # caused -1 TP regression on pathtraver-01 (10->9).
                if name == "traversal_passwd":
                    traversal_snap = snapshot
                    traversal_snap_payload = value
                    # ADR-028 D5: --verbose explains why this payload didn't contribute
                    # to the existence oracle. Emitted only on non-2xx; if a later payload
                    # is 2xx, the diagnostic is not emitted because traversal_snap is set.
                elif (
                    category == "traversal" and self.verbose and traversal_snap is None
                ):
                    _say(
                        f"  [{param}] traversal {name} returned {r.status_code}, "
                        f"not captured for existence oracle (2xx required)"
                    )

                if name == "sqli_blind_true":
                    sqli_blind_true_snap = snapshot
                    sqli_blind_true_status = r.status_code
                    sqli_blind_true_payload = value
                elif name == "sql_single_quote":
                    sqli_quote_snap = snapshot
                    sqli_quote_resp = r
                elif name == "sql_or_1eq1":
                    sqli_or_snap = snapshot
                    # sqli_or_resp previously assigned here was unused (F841);
                    # removed 2026-10-25 to unblock CI. The "or 1=1" response body
                    # should arguably be examined like sqli_quote_resp; Phase 1 audit.
                elif name == "ldap_wildcard":
                    ldap_wild_snap = snapshot
                    ldap_wild_resp = r
                # The trustbound marker is a purpose-built oracle
                # probe, not an attack string. Running the generic
                # analyzer on it labels any reflecting target with the
                # marker tuple's category, producing cross-category FPs
                # on crypto/hash/xss/securecookie. The oracle above is
                # the only consumer of this payload.
                if name == "trustbound_marker":
                    continue

                analyzer = DifferentialAnalyzer(
                    baseline=baseline,
                    payload_name=name,
                    payload_value=value,
                    payload_category=category,
                )
                raw_findings = analyzer.analyze(snapshot)

                for f in raw_findings:
                    if f.get("severity") == "info":
                        continue
                    # Evidence-grounded classification: a finding's class
                    # must come from the evidence, not the probe. A DB
                    # error signature is evidence of SQL injection
                    # regardless of which payload triggered it. Without
                    # this override, every probe family (xss, traversal,
                    # cmdi) that happens to trigger a SQL error gets
                    # stamped with its own category -- the structural
                    # misattribution class. See Amendment 12.
                    if f.get("type") == "db_error":
                        category = "sqli"
                    if f.get("type") == "command_output":
                        category = "cmdi"
                    if f.get("type") == "sql_result_rows":
                        category = "sqli"
                    if f.get("type") == "xpath_result_rows":
                        category = "xpathi"
                    if f.get("type") == "status_change":
                        # Phase 0.2(b): 4xx-baseline -> 5xx-payload IS a
                        # signal (the payload changed the code path). Emit
                        # it; CorroboratorConfirmer marks it unproven at the
                        # engine boundary. On a 2xx/3xx baseline the same
                        # observation is the /traversal misattribution shape
                        # (any unknown input 500s); suppress it.
                        baseline_status = baseline.modal_status
                        if not (400 <= baseline_status < 500):
                            continue
                    elif f.get("type") in CORROBORATOR_ONLY_TYPES:
                        # length_anomaly / length_shrink: still dropped
                        # unconditionally. A length delta does not
                        # distinguish a real bug from a reflection on any
                        # baseline shape; content-signature gates are needed.
                        continue
                    if f.get("type") == "payload_reflected" and category != "xss":
                        # Reflection on a non-xss probe is not evidence
                        # of that probe's category. The endpoint echoed
                        # our input; it did not execute SQL, read a file,
                        # or run a command. Stamping the probe's category
                        # on the echo is structural misattribution and
                        # produces false sqli/traversal findings on any
                        # target that reflects a header or parameter.
                        # xss is the one category where an unescaped echo
                        # *is* the bug, and it is emitted above as
                        # reflected_xss, not payload_reflected, so this
                        # gate never suppresses it.
                        continue
                    request_obj = getattr(r, "request", None)
                    candidate = CandidateFinding(
                        param=param,
                        payload_name=name,
                        payload_value=value,
                        category=category,
                        severity=f.get("severity", "low"),
                        finding_type=f.get("type", "unknown"),
                        detail=f.get("detail", ""),
                        response_status=r.status_code,
                        response_length=len(r.text or ""),
                        response_time=snapshot.elapsed,
                        reflection_context=f.get("reflection_context"),
                        response_content_type=snapshot.content_type,
                        url=getattr(request_obj, "url", None) or self.target,
                        method=self.method,
                        raw_request=serialize_request(request_obj),
                        raw_response=serialize_response(r),
                    )
                    result = _ENGINE.verify(candidate)
                    if not isinstance(result, VerifiedFinding):
                        # AnalyzerImplicitConfirmer always confirms well-formed
                        # candidates; reach here only if the candidate is
                        # malformed, which the analyzer precludes. Defensive.
                        continue
                    finding = _to_scan_finding(result)
                    summary.findings.append(finding)
                    summary.finding_count += 1
                    if not quiet:
                        _say(
                            f"  [{param}] {name} -> "
                            f"{finding.severity.upper()}: {finding.finding_type} "
                            f"| {finding.detail[:80]}"
                        )

            if summary.aborted:
                break

            # Paired-probe: sqli quote oracle.
            if sqli_quote_snap is not None and sqli_or_snap is not None:
                oracle = check_sqli_quote_oracle(
                    baseline=baseline,
                    quote_snapshot=sqli_quote_snap,
                    or_snapshot=sqli_or_snap,
                )
                for f in oracle:
                    req_obj = getattr(sqli_quote_resp, "request", None)
                    candidate = CandidateFinding(
                        param=param,
                        payload_name="sql_quote_oracle",
                        payload_value="'",
                        category="sqli",
                        severity=f.get("severity", "critical"),
                        finding_type=f.get("type", "sqli_quote_oracle"),
                        detail=f.get("detail", ""),
                        response_status=sqli_quote_resp.status_code,
                        response_length=len(sqli_quote_resp.text or ""),
                        response_time=sqli_quote_snap.elapsed,
                        response_content_type=sqli_quote_snap.content_type,
                        url=getattr(req_obj, "url", None) or self.target,
                        method=self.method,
                        raw_request=serialize_request(req_obj),
                        raw_response=serialize_response(sqli_quote_resp),
                    )
                    result = _ENGINE.verify(candidate)
                    if not isinstance(result, VerifiedFinding):
                        continue
                    finding = _to_scan_finding(result)
                    summary.findings.append(finding)
                    summary.finding_count += 1

            # Paired-probe: xpathi error oracle. Reuses the bare-quote
            # and balanced snapshots captured for the sqli quote oracle.
            # XPath sinks 500 on the quote with a parser error (not a
            # SQL error), so the sqli oracle stays silent and this one
            # fires. See Amendment 18.
            if sqli_quote_snap is not None and sqli_or_snap is not None:
                xo = check_xpath_error_oracle(
                    baseline=baseline,
                    quote_snapshot=sqli_quote_snap,
                    or_snapshot=sqli_or_snap,
                )
                for f in xo:
                    req_obj = getattr(sqli_quote_resp, "request", None)
                    candidate = CandidateFinding(
                        param=param,
                        payload_name="xpath_error_oracle",
                        payload_value="'",
                        category="xpathi",
                        severity=f.get("severity", "critical"),
                        finding_type=f.get("type", "xpathi_error_oracle"),
                        detail=f.get("detail", ""),
                        response_status=sqli_quote_resp.status_code,
                        response_length=len(sqli_quote_resp.text or ""),
                        response_time=sqli_quote_snap.elapsed,
                        response_content_type=sqli_quote_snap.content_type,
                        url=getattr(req_obj, "url", None) or self.target,
                        method=self.method,
                        raw_request=serialize_request(req_obj),
                        raw_response=serialize_response(sqli_quote_resp),
                    )
                    result = _ENGINE.verify(candidate)
                    if not isinstance(result, VerifiedFinding):
                        continue
                    finding = _to_scan_finding(result)
                    summary.findings.append(finding)
                    summary.finding_count += 1

            # Paired-probe: LDAP injection oracle.
            if ldap_wild_snap is not None:
                oracle = check_ldap_injection_oracle(
                    baseline=baseline,
                    wildcard_snapshot=ldap_wild_snap,
                )
                for f in oracle:
                    req_obj = getattr(ldap_wild_resp, "request", None)
                    candidate = CandidateFinding(
                        param=param,
                        payload_name="ldap_wildcard",
                        payload_value="*",
                        category="ldapi",
                        severity=f.get("severity", "critical"),
                        finding_type=f.get("type", "ldap_injection"),
                        detail=f.get("detail", ""),
                        response_status=ldap_wild_resp.status_code,
                        response_length=len(ldap_wild_resp.text or ""),
                        response_time=ldap_wild_snap.elapsed,
                        response_content_type=ldap_wild_snap.content_type,
                        url=getattr(req_obj, "url", None) or self.target,
                        method=self.method,
                        raw_request=serialize_request(req_obj),
                        raw_response=serialize_response(ldap_wild_resp),
                    )
                    result = _ENGINE.verify(candidate)
                    if not isinstance(result, VerifiedFinding):
                        continue
                    finding = _to_scan_finding(result)
                    summary.findings.append(finding)
                    summary.finding_count += 1
                    if not quiet:
                        _say(
                            f"  [{param}] ldap_wildcard -> "
                            f"{finding.severity.upper()}: {finding.finding_type} "
                            f"| {finding.detail[:80]}"
                        )
                    # Fire once: the wildcard snapshot is captured once,
                    # but the oracle call site sits inside the payload
                    # loop. Clear after first hit to avoid re-emitting
                    # on every subsequent payload iteration.
                    ldap_wild_snap = None
                    if not quiet:
                        _say(
                            f"  [{param}] {finding.payload_name} -> "
                            f"{finding.severity.upper()}: "
                            f"{finding.finding_type} "
                            f"| {finding.detail[:80]}"
                        )

            # Paired-probe: pathtraver existence oracle.
            if traversal_snap is not None and traversal_snap_payload is not None:
                noexist_path = (
                    traversal_snap_payload
                    + "_janissary_noexist_"
                    + self._traversal_nonce
                )
                try:
                    r2 = self._paced_request(self.target, param, noexist_path)
                except requests.RequestException:
                    r2 = None
                summary.total_requests += 1
                if r2 is not None:
                    snap2 = ResponseSnapshot.from_response(
                        r2, normalizer=self.normalizer
                    )
                    oracle = check_pathtraver_oracle(
                        baseline=baseline,
                        snapshot_exists=traversal_snap,
                        snapshot_noexist=snap2,
                        payload_exists=traversal_snap_payload,
                        payload_noexist=noexist_path,
                    )
                    for f in oracle:
                        req_obj = getattr(r2, "request", None)
                        candidate = CandidateFinding(
                            param=param,
                            payload_name="traversal_noexist_probe",
                            payload_value=noexist_path,
                            category="traversal",
                            severity=f.get("severity", "critical"),
                            finding_type=f.get("type", "pathtraver_existence_oracle"),
                            detail=f.get("detail", ""),
                            response_status=r2.status_code,
                            response_length=len(r2.text or ""),
                            response_time=snap2.elapsed,
                            response_content_type=snap2.content_type,
                            url=getattr(req_obj, "url", None) or self.target,
                            method=self.method,
                            raw_request=serialize_request(req_obj),
                            raw_response=serialize_response(r2),
                        )
                        result = _ENGINE.verify(candidate)
                        if not isinstance(result, VerifiedFinding):
                            continue
                        finding = _to_scan_finding(result)
                        summary.findings.append(finding)
                        summary.finding_count += 1
                        if not quiet:
                            _say(
                                f"  [{param}] {finding.payload_name} -> "
                                f"{finding.severity.upper()}: "
                                f"{finding.finding_type} "
                                f"| {finding.detail[:80]}"
                            )

                # Group findings by root cause so the summary reports bugs,
            # not raw evidence rows.

            if self.collaborator is not None:
                self._ssrf_phase(param, summary, quiet=quiet)
        from janissary.engine.grouping import group_findings

        summary.groups = group_findings(summary.findings)

        # Attach recon data to the summary.
        if self.waf_profile is not None:
            summary.waf = self.waf_profile.to_dict()
        if self._pacer is not None:
            summary.pacer = self._pacer.stats()

        return summary
