"""Minimal HTTP scanner that drives the differential detection engine.

This is the port of the original janissary.run_scan, reduced to the
essential path: baseline collection, payload dispatch, and finding
emission. WAF pacing, POST bodies, and multi-threading are added in
later passes.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from janissary.detection import (
    Baseline,
    DifferentialAnalyzer,
    ResponseSnapshot,
)
from janissary.recon import (
    AdaptivePacer,
    PacerConfig,
    WAFDetector,
    WAFProfile,
)

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
    ("xss_script", "<script>alert(1)</script>", "xss", "high"),
    ("xss_img", "<img src=x onerror=alert(1)>", "xss", "high"),
    ("traversal_passwd", "../../../etc/passwd", "traversal", "critical"),
    ("traversal_encoded", "..%2f..%2f..%2fetc%2fpasswd", "traversal", "critical"),
    ("cmdi_semicolon", "; cat /etc/passwd", "cmdi", "critical"),
    ("cmdi_sleep", "; sleep 5", "cmdi", "critical"),
]

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# -------------------------------------------------------------------
# URL BUILDING
# -------------------------------------------------------------------


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


@dataclass
class ScanSummary:
    target: str
    params: list[str]
    method: str
    total_requests: int = 0
    finding_count: int = 0
    aborted: bool = False
    abort_reason: str | None = None
    baselines: dict = field(default_factory=dict)
    findings: list[ScanFinding] = field(default_factory=list)
    groups: list = field(default_factory=list)
    waf: dict | None = None
    pacer: dict | None = None


# -------------------------------------------------------------------
# SCANNER
# -------------------------------------------------------------------


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
        self._ua = DEFAULT_USER_AGENT
        self.detect_waf = detect_waf

        cfg = pacer_config or PacerConfig(base_delay=delay)
        if cfg.min_delay < delay:
            cfg.min_delay = delay
        self.pacer_config = cfg

        self.waf_profile: WAFProfile | None = None
        self._pacer: AdaptivePacer | None = None

    # ---------------------------------------------------------------

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

    def _request(self, url: str, param: str, value: str) -> requests.Response | None:
        if self.method == "POST":
            return self.session.post(
                self.target,
                headers=self._headers(),
                data={param: value},
                timeout=self.timeout,
                allow_redirects=False,
                proxies=self.proxies,
            )
        return self.session.get(
            build_url(url, param, value),
            headers=self._headers(),
            timeout=self.timeout,
            allow_redirects=False,
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
        """One request to confirm the endpoint responds."""
        try:
            r = self.session.get(
                self.target,
                headers=self._headers(),
                timeout=self.timeout,
                allow_redirects=False,
                proxies=self.proxies,
            )
        except requests.RequestException as e:
            return False, f"request error: {e}"
        if r.status_code >= 400:
            return False, f"HTTP {r.status_code}"
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
            print("[*] Probing for WAF...")
        profile = detector.detect(self.target)
        if not quiet:
            if profile.detected:
                vendor = profile.vendor or "unknown"
                print(
                    f"    WAF detected: {vendor} (confidence {profile.confidence:.2f})"
                )
            else:
                print("    No WAF signatures observed")
        return profile

    # ---------------------------------------------------------------

    def collect_baseline(self, param: str) -> Baseline:
        baseline = Baseline()
        benign = ["1", "test", "index", "home", "default"]
        for i in range(self.baseline_count):
            value = benign[i % len(benign)]
            try:
                r = self._paced_request(self.target, param, value)
            except requests.RequestException:
                continue
            if r is None:
                continue
            baseline.add(ResponseSnapshot.from_response(r))
        return baseline

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
            print(f"[*] Initial inter-request delay: {self._pacer.delay:.2f}s")

        for param in self.params:
            baseline = self.collect_baseline(param)
            summary.total_requests += self.baseline_count
            summary.baselines[param] = {
                "samples": len(baseline.snapshots),
                "mean_elapsed": round(baseline.mean_elapsed, 4),
                "std_elapsed": round(baseline.std_elapsed, 4),
                "stable_body": baseline.is_stable_body,
                "has_oracle": baseline.has_oracle,
            }

            if baseline.is_static and not quiet:
                print(f"  [{param}] baseline is static - timing gates disabled")

            for name, value, category, _severity in DEFAULT_PAYLOADS:
                try:
                    r = self._paced_request(self.target, param, value)
                except requests.RequestException as e:
                    if not quiet:
                        print(f"  [{param}] {name} - error: {e}")
                    continue
                summary.total_requests += 1
                if r is None:
                    continue

                snapshot = ResponseSnapshot.from_response(r)
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
                    finding = ScanFinding(
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
                    )
                    summary.findings.append(finding)
                    summary.finding_count += 1
                    if not quiet:
                        print(
                            f"  [{param}] {name} -> "
                            f"{finding.severity.upper()}: {finding.finding_type} "
                            f"| {finding.detail[:80]}"
                        )

                # Group findings by root cause so the summary reports bugs,
        # not raw evidence rows.
        from janissary.engine.grouping import group_findings

        summary.groups = group_findings(summary.findings)

        # Attach recon data to the summary.
        if self.waf_profile is not None:
            summary.waf = self.waf_profile.to_dict()
        if self._pacer is not None:
            summary.pacer = self._pacer.stats()

        return summary
