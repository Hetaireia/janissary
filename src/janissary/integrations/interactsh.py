"""Native Interactsh OOB client (ADR-015).

Extends ADR-012 D1 with a first-class `--interactsh` path:
JANISSARY registers with a ProjectDiscovery Interactsh server,
derives a correlation domain, and speaks the RSA-OAEP + AES-CFB
transport natively. No external binary required.

Interface parity with `CollaboratorClient` (ADR-015 D2) so
`Scanner._ssrf_phase` needs no changes:

    new_unique_id(payload_name) -> str
    payload_for(payload, uniq) -> str
    poll(uniq) -> list[SsrfHit]
"""

from __future__ import annotations

import base64
import json
import secrets
import string
from urllib.parse import urlparse

import requests

from janissary.integrations.collaborator import (
    CollaboratorError,
    SsrfHit,
    SsrfPayload,
)

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as _asym_padding
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.hazmat.primitives.ciphers import (
        Cipher as _Cipher,
        algorithms as _algorithms,
    )

    try:
        from cryptography.hazmat.decrepit.ciphers.modes import CFB as _CFB
    except ImportError:  # cryptography < 43
        from cryptography.hazmat.primitives.ciphers.modes import CFB as _CFB
    _CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover -- tested via test_requires_crypto
    _CRYPTO_AVAILABLE = False


DEFAULT_SERVERS = (
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.fun",
    "oast.me",
)

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def _require_crypto() -> None:
    if not _CRYPTO_AVAILABLE:
        raise CollaboratorError(
            "interactsh requires the 'cryptography' package; "
            "install with: pip install 'janissary[oob]'"
        )


class InteractshClient:
    """Native Interactsh OOB client (ADR-015 D1-D2).

    Registers with a ProjectDiscovery Interactsh server, decrypts
    RSA-OAEP / AES-CFB poll responses, and returns `SsrfHit` objects
    identical to `CollaboratorClient.poll()`.
    """

    def __init__(
        self,
        server: str | None = None,
        token: str | None = None,
        timeout: float = 10.0,
        session: requests.Session | None = None,
        user_agent: str | None = None,
    ) -> None:
        _require_crypto()
        self.timeout = timeout
        self.session = session or requests.Session()
        self.user_agent = user_agent or DEFAULT_UA
        self.token = token
        self._issued: dict[str, str] = {}
        self._private_key = None
        self._correlation_id = ""
        self._secret_key_b64 = ""
        self.server = ""
        candidates = [server] if server else list(DEFAULT_SERVERS)
        last_error: Exception | None = None
        for candidate in candidates:
            try:
                self._register(candidate)
                break
            except CollaboratorError as exc:
                last_error = exc
        else:
            raise CollaboratorError(
                f"interactsh registration failed on all servers: {last_error}"
            )

    # ------------------------------------------------------------------
    # registration
    # ------------------------------------------------------------------

    def _register(self, server: str) -> None:
        if "://" in server:
            base_url = server.rstrip("/")
            host = urlparse(server).hostname or server
        else:
            host = server.strip().rstrip("/")
            base_url = f"https://{host}"
        self._private_key = _rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        pub_pem = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1,
        )
        self._secret_key_b64 = base64.b64encode(secrets.token_bytes(32)).decode()
        self._correlation_id = "".join(
            secrets.choice(string.ascii_lowercase + string.digits) for _ in range(20)
        )
        body = {
            "public-key": base64.b64encode(pub_pem).decode(),
            "secret-key": self._secret_key_b64,
            "correlation-id": self._correlation_id,
        }
        headers = self._headers()
        if self.token:
            headers["Authorization"] = self.token
        url = f"{base_url}/register"
        try:
            r = self.session.post(url, json=body, headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:
            raise CollaboratorError(f"interactsh register failed: {exc}") from exc
        if r.status_code != 200:
            raise CollaboratorError(
                f"interactsh register HTTP {r.status_code}: {r.text[:200]}"
            )
        self.server = host

    # ------------------------------------------------------------------
    # CollaboratorClient interface (ADR-015 D2)
    # ------------------------------------------------------------------

    @property
    def base_domain(self) -> str:
        return f"{self._correlation_id}.{self.server}"

    def new_unique_id(self, payload_name: str = "") -> str:
        # 20-char uniq = exact match against Interactsh 'unique-id'
        uniq = "jns-" + secrets.token_hex(8)
        if payload_name:
            self._issued[uniq] = payload_name
        return uniq

    def payload_for(self, payload: SsrfPayload, uniq: str) -> str:
        return payload.url_template.format(uniq=uniq, collab=self.base_domain)

    def poll(self, uniq: str) -> list[SsrfHit]:
        url = f"https://{self.server}/poll"
        params = {"id": self._correlation_id, "secret": self._secret_key_b64}
        headers = self._headers()
        if self.token:
            headers["Authorization"] = self.token
        try:
            r = self.session.get(
                url, params=params, headers=headers, timeout=self.timeout
            )
        except requests.RequestException as exc:
            raise CollaboratorError(f"interactsh poll failed: {exc}") from exc
        if r.status_code in (204, 404):
            return []
        if r.status_code >= 400:
            raise CollaboratorError(f"interactsh poll HTTP {r.status_code}")
        try:
            data = r.json()
        except ValueError:
            return []
        aes_key_enc = data.get("aes_key") or ""
        entries = data.get("data") or []
        if not aes_key_enc or not isinstance(entries, list):
            return []

        aes_key = self._decrypt_aes_key(aes_key_enc)
        hits: list[SsrfHit] = []
        for entry_b64 in entries:
            entry = self._decrypt_entry(entry_b64, aes_key)
            if not entry:
                continue
            matched_uniq = self._match_uniq(entry, uniq)
            if not matched_uniq:
                continue
            hits.append(
                SsrfHit(
                    protocol=str(entry.get("protocol", "")).lower(),
                    payload_name=self._issued.get(matched_uniq, ""),
                    subdomain=matched_uniq,
                    source_ip=str(entry.get("remote-address", "")),
                    timestamp=str(entry.get("timestamp", "")),
                    raw=entry,
                )
            )
        return hits

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict:
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }

    def _decrypt_aes_key(self, aes_key_enc: str) -> bytes:
        try:
            return self._private_key.decrypt(
                base64.b64decode(aes_key_enc),
                _asym_padding.OAEP(
                    mgf=_asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as exc:
            raise CollaboratorError(
                f"interactsh aes_key decrypt failed: {exc}"
            ) from exc

    def _decrypt_entry(self, entry_b64: str, aes_key: bytes) -> dict | None:
        try:
            raw = base64.b64decode(entry_b64)
            iv, ct = raw[:16], raw[16:]
            decryptor = _Cipher(_algorithms.AES(aes_key), _CFB(iv)).decryptor()
            plaintext = decryptor.update(ct) + decryptor.finalize()
            parsed = json.loads(plaintext)
            return parsed if isinstance(parsed, dict) else None
        except Exception:
            return None

    def _match_uniq(self, entry: dict, expected: str) -> str:
        full_id = str(entry.get("full-id", ""))
        unique_id = str(entry.get("unique-id", ""))
        for issued in self._issued:
            if issued == unique_id or issued in full_id:
                return issued
        if expected and (expected == unique_id or expected in full_id):
            return expected
        return ""

    def close(self) -> None:
        try:
            self.session.close()
        except Exception:
            pass
