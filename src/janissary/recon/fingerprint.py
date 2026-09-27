"""Platform fingerprinting for JANISSARY.

Collects cheap, non-destructive signals about a target and merges them
into a single identity: server software, CMS, framework, favicon hash,
common CMS paths, cookies, and meta tags. Intended to run after WAF
detection so a caller can carry both the WAF profile and the platform
profile in one result.

Nothing here fuzzes, probes credentials, or sends any attack payload.
Every request is a plain GET for a public resource.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

import requests

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# ---------------------------------------------------------------------------
# Signal tables
# ---------------------------------------------------------------------------

# CMS path probes. A 200/3xx on these is a strong signal; a 403 on a
# known login path is also informative.
CMS_PATHS: dict[str, tuple[str, ...]] = {
    "wordpress": (
        "/wp-login.php",
        "/wp-admin/",
        "/wp-content/",
        "/wp-includes/",
    ),
    "drupal": (
        "/user/login",
        "/core/install.php",
        "/sites/default/",
        "/CHANGELOG.txt",
    ),
    "joomla": (
        "/administrator/",
        "/components/",
        "/templates/",
        "/configuration.php-dist",
    ),
    "magento": (
        "/admin/",
        "/downloader/",
        "/js/mage/",
        "/skin/frontend/",
    ),
    "ghost": (
        "/ghost/",
        "/assets/built/",
    ),
    "typo3": (
        "/typo3/",
        "/typo3conf/",
        "/typo3temp/",
    ),
}

# Cookie name -> CMS. WordPress and Drupal both prefix session
# cookies; the prefix alone is a reliable tell.
COOKIE_SIGNATURES: dict[str, str] = {
    "wordpress_": "wordpress",
    "wp-settings": "wordpress",
    "woocommerce_": "wordpress",
    "drupal": "drupal",
    "SESS": "drupal",  # only when combined with other Drupal signals
    "joomla": "joomla",
    "frontend": "magento",
    "adminhtml": "magento",
    "typo3_": "typo3",
    "ghost-": "ghost",
    "PHPSESSID": "php",
    "JSESSIONID": "java",
    "ASP.NET_SessionId": "aspnet",
    "connect.sid": "express",
    "laravel_session": "laravel",
    "csrftoken": "django",
    "sessionid": "django",
}

# Server / X-Powered-By substring -> technology label.
SERVER_SIGNATURES: dict[str, tuple[str, ...]] = {
    "nginx": ("nginx",),
    "apache": ("apache",),
    "iis": ("microsoft-iis",),
    "caddy": ("caddy",),
    "litespeed": ("litespeed",),
    "openresty": ("openresty",),
    "gunicorn": ("gunicorn",),
    "uvicorn": ("uvicorn",),
    "werkzeug": ("werkzeug",),
    "php": ("php",),
    "aspnet": ("asp.net",),
    "express": ("express",),
    "rails": ("phusion passenger", "mod_rails"),
    "python": ("python",),
}

# Meta generator value -> framework/CMS.
GENERATOR_SIGNATURES: dict[str, tuple[str, ...]] = {
    "wordpress": ("wordpress",),
    "drupal": ("drupal",),
    "joomla": ("joomla",),
    "typo3": ("typo3",),
    "ghost": ("ghost",),
    "hugo": ("hugo",),
    "jekyll": ("jekyll",),
    "gatsby": ("gatsby",),
    "nextjs": ("next.js",),
    "nuxt": ("nuxt",),
    "django": ("django",),
    "rails": ("ruby on rails",),
    "laravel": ("laravel",),
    "symfony": ("symfony",),
}

GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

SERVER_VERSION_RE = re.compile(r"/[\d.]+")

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class Fingerprint:
    target: str
    reachable: bool = False
    status: int | None = None
    server: str = ""
    powered_by: str = ""
    cms: str | None = None
    cms_confidence: float = 0.0
    technologies: list[str] = field(default_factory=list)
    paths_found: dict[str, int] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)
    meta_generator: str | None = None
    favicon_hash: str | None = None
    title: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "reachable": self.reachable,
            "status": self.status,
            "server": self.server,
            "powered_by": self.powered_by,
            "cms": self.cms,
            "cms_confidence": round(self.cms_confidence, 3),
            "technologies": list(self.technologies),
            "paths_found": dict(self.paths_found),
            "cookies": list(self.cookies),
            "meta_generator": self.meta_generator,
            "favicon_hash": self.favicon_hash,
            "title": self.title,
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _extract_title(text: str) -> str | None:
    m = TITLE_RE.search(text or "")
    if not m:
        return None
    return m.group(1).strip()[:200] or None


def _extract_generator(text: str) -> str | None:
    m = GENERATOR_RE.search(text or "")
    if not m:
        return None
    return m.group(1).strip() or None


def _match_tech(value: str, table: dict[str, tuple[str, ...]]) -> list[str]:
    if not value:
        return []
    low = value.lower()
    return [name for name, needles in table.items() if any(n in low for n in needles)]


def _classify_cookie(name: str) -> str | None:
    for prefix, tech in COOKIE_SIGNATURES.items():
        if name == prefix or name.startswith(prefix):
            return tech
    return None


def _favicon_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Fingerprinter
# ---------------------------------------------------------------------------


class Fingerprinter:
    def __init__(
        self,
        target: str,
        timeout: float = 10.0,
        proxies: dict | None = None,
        session: requests.Session | None = None,
        user_agent: str | None = None,
        probe_cms_paths: bool = True,
        probe_favicon: bool = True,
    ) -> None:
        self.target = target
        self.timeout = timeout
        self.proxies = proxies
        self.session = session or requests.Session()
        self.user_agent = user_agent or DEFAULT_UA
        self.probe_cms_paths = probe_cms_paths
        self.probe_favicon = probe_favicon

    def _headers(self) -> dict:
        return {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
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

    # ---------------------------------------------------------------

    def run(self) -> Fingerprint:
        fp = Fingerprint(target=self.target)

        home = self._get(self.target)
        if home is None:
            fp.notes.append("home page request failed")
            return fp

        fp.status = home.status_code
        fp.reachable = home.status_code < 500
        fp.server = home.headers.get("Server", "")
        fp.powered_by = home.headers.get("X-Powered-By", "")
        fp.cookies = list(home.cookies.keys()) or list(
            dict.fromkeys(
                c.split("=", 1)[0].strip()
                for c in home.headers.get("Set-Cookie", "").split(";")
                if "=" in c
            )
        )

        body = home.text or ""
        fp.meta_generator = _extract_generator(body)
        fp.title = _extract_title(body)

        # --- tech stack from headers -----------------------------------
        techs: set[str] = set()
        techs.update(_match_tech(fp.server, SERVER_SIGNATURES))
        techs.update(_match_tech(fp.powered_by, SERVER_SIGNATURES))
        if fp.meta_generator:
            techs.update(_match_tech(fp.meta_generator, GENERATOR_SIGNATURES))

        # --- CMS from cookies ------------------------------------------
        cms_votes: dict[str, int] = {}
        for cookie in fp.cookies:
            cms = _classify_cookie(cookie)
            if cms in ("wordpress", "drupal", "joomla", "magento", "typo3", "ghost"):
                cms_votes[cms] = cms_votes.get(cms, 0) + 1

        if fp.meta_generator:
            for cms in GENERATOR_SIGNATURES:
                if cms in (fp.meta_generator or "").lower():
                    cms_votes[cms] = cms_votes.get(cms, 0) + 2

        # --- CMS from paths --------------------------------------------
        if self.probe_cms_paths:
            self._probe_cms_paths(fp, cms_votes)

        # --- favicon ---------------------------------------------------
        if self.probe_favicon:
            self._probe_favicon(fp)

        # --- finalize CMS ----------------------------------------------
        if cms_votes:
            best, votes = max(cms_votes.items(), key=lambda kv: kv[1])
            fp.cms = best
            fp.cms_confidence = min(1.0, 0.4 + 0.15 * votes)

        # Server / powered_by are useful as technology labels even
        # without version numbers, so add them verbatim.
        if fp.server:
            techs.add(fp.server.split("/")[0].lower())
        if fp.powered_by:
            techs.add(fp.powered_by.split("/")[0].lower())

        fp.technologies = sorted(t for t in techs if t)
        return fp

    # ---------------------------------------------------------------

    def _probe_cms_paths(self, fp: Fingerprint, cms_votes: dict[str, int]) -> None:
        for cms, paths in CMS_PATHS.items():
            hits = 0
            for path in paths:
                url = urljoin(self.target, path)
                r = self._get(url)
                if r is None:
                    continue
                fp.paths_found[path] = r.status_code
                # 200 = present, 401/403 = present but protected.
                if r.status_code in (200, 201, 301, 302, 401, 403):
                    hits += 1
            if hits >= 2:
                cms_votes[cms] = cms_votes.get(cms, 0) + hits

    def _probe_favicon(self, fp: Fingerprint) -> None:
        url = urljoin(self.target, "/favicon.ico")
        r = self._get(url)
        if r is None or r.status_code != 200:
            return
        data = r.content or b""
        if not data:
            return
        fp.favicon_hash = _favicon_hash(data)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def fingerprint(
    target: str,
    timeout: float = 10.0,
    proxies: dict | None = None,
    session: requests.Session | None = None,
    probe_cms_paths: bool = True,
    probe_favicon: bool = True,
) -> Fingerprint:
    """Fingerprint a target and return the merged result."""
    f = Fingerprinter(
        target=target,
        timeout=timeout,
        proxies=proxies,
        session=session,
        probe_cms_paths=probe_cms_paths,
        probe_favicon=probe_favicon,
    )
    return f.run()
