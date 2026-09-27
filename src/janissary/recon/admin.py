"""Admin panel discovery.

Probes a small, curated set of well-known administrative and
management endpoints and reports what each one looks like:

- HTTP status (including redirect targets),
- whether the response contains a login form (a ``<form>`` with a
  password input),
- whether the response leaks a version string in the title, a
  ``generator`` meta tag, or a known framework banner.

The module never submits credentials and never attempts default
logins. It is purely identification: does the path exist, what is
it, and does it disclose anything useful.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

import requests

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# ---------------------------------------------------------------------------
# Admin path table
# ---------------------------------------------------------------------------

ADMIN_PATHS: dict[str, tuple[str, ...]] = {
    "wordpress": (
        "/wp-admin/",
        "/wp-login.php",
        "/wp-admin/install.php",
    ),
    "drupal": (
        "/user/login",
        "/admin/",
        "/admin/config",
    ),
    "joomla": (
        "/administrator/",
        "/administrator/index.php",
    ),
    "magento": (
        "/admin/",
        "/admin/admin/",
        "/downloader/",
    ),
    "ghost": (
        "/ghost/",
        "/ghost/#/signin",
    ),
    "typo3": (
        "/typo3/",
        "/typo3/login",
    ),
    "tomcat": (
        "/manager/html",
        "/host-manager/html",
        "/manager/status",
    ),
    "jenkins": (
        "/manage",
        "/login",
        "/script",
    ),
    "grafana": (
        "/login",
        "/admin",
    ),
    "kibana": (
        "/app/kibana",
        "/app/monitoring",
    ),
    "prometheus": (
        "/graph",
        "/targets",
    ),
    "kubernetes": (
        "/api/v1/namespaces",
        "/apis",
        "/healthz",
    ),
    "phpmyadmin": (
        "/phpmyadmin/",
        "/pma/",
        "/mysql/",
    ),
    "cpanel": (
        "/cpanel",
        "/webmail",
    ),
    "plesk": (
        "/plesk/",
        "/login_up.php",
    ),
    "webmin": (
        "/webmin/",
        "/webmin/login.cgi",
    ),
    "rabbitmq": (
        "/rabbitmq/",
        "/rabbitmq/#/",
    ),
    "elasticsearch": (
        "/_cluster/health",
        "/_cat/indices",
    ),
}

# Technologies where a 401/403 response is itself an admin signal.
PROTECTED_IS_HIT = frozenset(
    {"tomcat", "jenkins", "kubernetes", "phpmyadmin", "grafana"}
)

# ---------------------------------------------------------------------------
# Detection regexes
# ---------------------------------------------------------------------------

PASSWORD_INPUT_RE = re.compile(r'<input[^>]+type=["\']password["\']', re.IGNORECASE)
FORM_RE = re.compile(r"<form\b", re.IGNORECASE)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
VERSION_HINT_RE = re.compile(
    r"(?:version|v)\s*[:=]?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)
SERVER_BANNER_RE = re.compile(
    r"^(?:Apache|nginx|IIS|Tomcat|Jetty|Grafana|Kibana)\b.*",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class AdminHit:
    platform: str
    path: str
    status: int | None
    location: str = ""
    is_login_form: bool = False
    title: str = ""
    version_hint: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "platform": self.platform,
            "path": self.path,
            "status": self.status,
            "location": self.location,
            "is_login_form": self.is_login_form,
            "title": self.title,
            "version_hint": self.version_hint,
            "notes": list(self.notes),
        }


@dataclass
class AdminProfile:
    target: str
    reachable: bool = False
    hits: list[AdminHit] = field(default_factory=list)
    paths_probed: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "reachable": self.reachable,
            "paths_probed": self.paths_probed,
            "hits": [h.to_dict() for h in self.hits],
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Probing
# ---------------------------------------------------------------------------


class AdminProbe:
    def __init__(
        self,
        target: str,
        timeout: float = 10.0,
        proxies: dict | None = None,
        session: requests.Session | None = None,
        user_agent: str | None = None,
        custom_paths: dict[str, tuple[str, ...]] | None = None,
    ) -> None:
        self.target = target
        self.timeout = timeout
        self.proxies = proxies
        self.session = session or requests.Session()
        self.user_agent = user_agent or DEFAULT_UA
        self.paths = custom_paths if custom_paths is not None else ADMIN_PATHS

    def _headers(self) -> dict:
        return {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/json,*/*;q=0.8",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }

    def _get(self, url: str) -> requests.Response | None:
        try:
            return self.session.get(
                url,
                headers=self._headers(),
                timeout=self.timeout,
                allow_redirects=False,
                proxies=self.proxies,
            )
        except requests.RequestException:
            return None

    def run(self) -> AdminProfile:
        profile = AdminProfile(target=self.target)

        # Baseline request to confirm the target is alive.
        home = self._get(self.target)
        if home is None:
            profile.notes.append("baseline request failed")
            return profile
        profile.reachable = True

        for platform, paths in self.paths.items():
            for path in paths:
                url = urljoin(self.target, path)
                r = self._get(url)
                profile.paths_probed += 1
                if r is None:
                    continue
                hit = self._classify(platform, path, r)
                if hit is not None:
                    profile.hits.append(hit)

        return profile

    def _classify(
        self, platform: str, path: str, r: requests.Response
    ) -> AdminHit | None:
        status = r.status_code
        location = r.headers.get("Location", "")
        body = r.text or ""

        # ---- Decide whether this is a hit at all ----
        is_hit = False
        if status in (200, 201):
            is_hit = True
        elif status in (301, 302, 303, 307, 308):
            # A redirect to a login path is a hit; a redirect to a
            # generic "not found" page is not.
            lowered = location.lower()
            if (
                path.lower().rstrip("/") in lowered
                or "login" in lowered
                or "signin" in lowered
            ):
                is_hit = True
        elif status in (401, 403) and platform in PROTECTED_IS_HIT:
            is_hit = True

        if not is_hit:
            return None

        # ---- Extract details ----
        title = ""
        m = TITLE_RE.search(body)
        if m:
            title = m.group(1).strip()[:120]

        version_hint = ""
        gm = GENERATOR_RE.search(body)
        if gm:
            version_hint = gm.group(1).strip()
        else:
            vm = VERSION_HINT_RE.search(body[:4096])
            if vm:
                version_hint = vm.group(1)
        if not version_hint:
            sb = SERVER_BANNER_RE.search(r.headers.get("Server", "") or "")
            if sb:
                server = r.headers.get("Server", "")
                vm = re.search(r"[\d.]+", server)
                if vm:
                    version_hint = vm.group(0)

        is_login_form = bool(PASSWORD_INPUT_RE.search(body) and FORM_RE.search(body))

        notes: list[str] = []
        if status in (401, 403):
            notes.append("access protected")
        if "X-Powered-By" in r.headers:
            notes.append(f"X-Powered-By: {r.headers['X-Powered-By']}")

        return AdminHit(
            platform=platform,
            path=path,
            status=status,
            location=location,
            is_login_form=is_login_form,
            title=title,
            version_hint=version_hint,
            notes=notes,
        )


# ---------------------------------------------------------------------------
# Convenience entry point
# ---------------------------------------------------------------------------


def probe_admin(
    target: str,
    timeout: float = 10.0,
    proxies: dict | None = None,
    session: requests.Session | None = None,
    custom_paths: dict[str, tuple[str, ...]] | None = None,
) -> AdminProfile:
    return AdminProbe(
        target=target,
        timeout=timeout,
        proxies=proxies,
        session=session,
        custom_paths=custom_paths,
    ).run()
