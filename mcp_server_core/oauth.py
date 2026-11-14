"""OAuth 2.1 and RFC 9728 Protected Resource Implementation for ChatGPT and Remote Agents.

Implements MCP 2025-11-25 Authorization Specification:
- RFC 9728: OAuth 2.0 Protected Resource Metadata
- RFC 8414: OAuth 2.0 Authorization Server Metadata
- RFC 7591: Dynamic Client Registration (DCR)
- RFC 7636: Proof Key for Code Exchange (PKCE S256)
- Embedded Local Authorization Server & SQLite Persistent Storage
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import html
import ipaddress
import json
import os
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from .constants import (
    DEFAULT_CHATGPT_REDIRECT_URIS,
    DEFAULT_OAUTH_SCOPES,
)
from .env import get_runtime_dir

DEFAULT_PRESET_REDIRECT_URIS: list[str] = DEFAULT_CHATGPT_REDIRECT_URIS


def base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string without padding."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def is_loopback_address(host: str) -> bool:
    """Check whether a host string is a local loopback address."""
    h = host.lower()
    if h in ("localhost", "127.0.0.1", "::1", "[::1]"):
        return True
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return ip.is_loopback
    except ValueError:
        return False


def validate_redirect_uri(uri: str) -> tuple[bool, str]:
    """Validate OAuth 2.1 redirect_uri safety and scheme requirements according to RFC 6749 & RFC 8252."""
    if not uri or not isinstance(uri, str):
        return False, "redirect_uri is required and must be a string"
    if len(uri) > 2048:
        return False, "redirect_uri exceeds maximum length of 2048 characters"
    try:
        parsed = urlparse(uri)
    except Exception:
        return False, "Invalid redirect_uri format"

    if not parsed.scheme:
        return False, "redirect_uri must include a scheme"

    scheme = parsed.scheme.lower()
    if scheme in ("javascript", "data", "vbscript", "file", "about"):
        return False, f"Dangerous redirect_uri scheme: {scheme}"

    if parsed.fragment:
        return False, "redirect_uri must not contain a fragment identifier (#)"

    if not parsed.netloc:
        return False, "redirect_uri must contain a valid network location (host)"

    hostname = parsed.hostname
    if not hostname:
        return False, "redirect_uri must contain a valid host"

    # RFC 8252 / OAuth 2.1: Native apps may use http on loopback interfaces
    if scheme == "http":
        if not is_loopback_address(hostname):
            return False, "HTTP scheme is only permitted for loopback addresses (127.0.0.1, localhost)"
        return True, ""

    if scheme == "https":
        return True, ""

    return False, f"Unsupported redirect_uri scheme: {scheme} (only https or loopback http allowed)"


def get_allowed_redirect_uris(env_cfg: Any = None) -> list[str]:
    """Load additional administrator-whitelisted redirect URIs from config or MCP_ALLOWED_REDIRECT_URIS."""
    if env_cfg and hasattr(env_cfg, "allowed_redirect_uris") and env_cfg.allowed_redirect_uris:
        return list(env_cfg.allowed_redirect_uris)
    env_val = os.getenv("MCP_ALLOWED_REDIRECT_URIS", "").strip()
    if not env_val:
        return []
    return [u.strip() for u in env_val.split(",") if u.strip()]


def is_uri_allowed_for_client(
    client_id: str,
    redirect_uri: str,
    registered_client: dict[str, Any] | None = None,
    oauth_server: LocalOAuthServer | None = None,
    env_cfg: Any = None,
    strict_client: bool | None = None,
    allowed_redirect_uris: list[str] | None = None,
    preset_client_id: str | None = None,
) -> bool:
    """Check whether a redirect_uri is authorized for the given client."""
    if not client_id or not client_id.strip():
        return False

    eff_preset_id = (
        preset_client_id
        if preset_client_id is not None
        else (
            getattr(oauth_server, "preset_client_id", None)
            if oauth_server is not None
            else (
                getattr(env_cfg, "preset_client_id", None)
                if env_cfg is not None
                else os.getenv("MCP_PRESET_CLIENT_ID", "chatgpt").strip() or "chatgpt"
            )
        )
    ) or "chatgpt"

    eff_extra_allowed = (
        allowed_redirect_uris
        if allowed_redirect_uris is not None
        else (
            getattr(oauth_server, "allowed_redirect_uris", None)
            if oauth_server is not None
            else (
                getattr(env_cfg, "allowed_redirect_uris", None)
                if env_cfg is not None
                else get_allowed_redirect_uris()
            )
        )
    ) or []

    if redirect_uri in eff_extra_allowed:
        return True

    # 1. Preset client (e.g. ChatGPT) - strictly enforce whitelist
    if client_id == eff_preset_id:
        allowed = list(DEFAULT_PRESET_REDIRECT_URIS) + list(eff_extra_allowed)
        if registered_client and registered_client.get("redirect_uris"):
            allowed.extend(registered_client["redirect_uris"])
        # Support official connector platform redirects
        if redirect_uri.startswith("https://chatgpt.com/connector/oauth/"):
            return True
        if redirect_uri in allowed:
            return True
        try:
            parsed = urlparse(redirect_uri)
            if parsed.scheme.lower() == "http" and parsed.hostname and is_loopback_address(parsed.hostname):
                return True
        except Exception:
            pass
        return False

    # 2. Registered client in database
    if registered_client:
        registered_uris = registered_client.get("redirect_uris") or []
        if registered_uris:
            return redirect_uri in registered_uris
        try:
            parsed = urlparse(redirect_uri)
            if parsed.scheme.lower() == "http" and parsed.hostname and is_loopback_address(parsed.hostname):
                return True
        except Exception:
            pass
        return redirect_uri in eff_extra_allowed

    # 3. Unregistered / ad-hoc client
    # By default, strict mode is ON (1): only registered DCR clients or preset clients are authorized.
    eff_strict = (
        strict_client
        if strict_client is not None
        else (
            getattr(oauth_server, "strict_client", None)
            if oauth_server is not None
            else (
                getattr(env_cfg, "oauth_strict_client", None)
                if env_cfg is not None
                else os.getenv("MCP_OAUTH_STRICT_CLIENT", "1").strip().lower() not in ("0", "false", "no")
            )
        )
    )
    if eff_strict:
        return False
    return True


def verify_pkce(
    code_verifier: str,
    code_challenge: str,
    method: str = "S256",
    allow_plain: bool | None = None,
    env_cfg: Any = None,
) -> bool:
    """Verify PKCE code_verifier against code_challenge according to RFC 7636."""
    if not code_verifier or not code_challenge:
        return False
    eff_plain = (
        allow_plain
        if allow_plain is not None
        else (
            getattr(env_cfg, "oauth_allow_plain_pkce", None)
            if env_cfg is not None
            else os.getenv("MCP_OAUTH_ALLOW_PLAIN_PKCE", "0").strip().lower() in ("1", "true", "yes")
        )
    )
    strict_len = (
        getattr(env_cfg, "oauth_strict_pkce", None)
        if env_cfg is not None
        else os.getenv("MCP_OAUTH_STRICT_PKCE", "0").strip().lower() in ("1", "true", "yes")
    )
    if strict_len and (len(code_verifier) < 43 or len(code_verifier) > 128):
        return False
    if method == "plain":
        if not eff_plain:
            return False
        return code_verifier == code_challenge
    elif method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = base64url_encode(digest)
        return computed == code_challenge
    return False


def is_trusted_proxy(
    ip_str: str,
    trust_override: bool | None = None,
    env_cfg: Any = None,
) -> bool:
    """Check if the immediate peer IP is a trusted private/loopback proxy."""
    eff_trust = (
        trust_override
        if trust_override is not None
        else (
            getattr(env_cfg, "trust_proxy_headers", None)
            if env_cfg is not None
            else None
        )
    )
    if eff_trust is True:
        return True
    elif eff_trust is False:
        pass
    else:
        trust_env = os.getenv("MCP_TRUST_PROXY_HEADERS", "").strip().lower()
        if trust_env in ("1", "true", "yes", "always"):
            return True
        if trust_env in ("0", "false", "no", "never"):
            return False

    try:
        ip = ipaddress.ip_address(ip_str.strip("[]"))
        return ip.is_loopback or ip.is_private
    except ValueError:
        return False


def get_client_ip(
    request: Request,
    trust_override: bool | None = None,
    env_cfg: Any = None,
) -> str:
    """Extract real client IP considering reverse proxy headers only from trusted proxies."""
    client = getattr(request, "client", None)
    host_val = getattr(client, "host", None) if client else None
    peer_ip = host_val if isinstance(host_val, str) else "127.0.0.1"
    if is_trusted_proxy(peer_ip, trust_override=trust_override, env_cfg=env_cfg):
        cf_connecting_ip = request.headers.get("cf-connecting-ip")
        if cf_connecting_ip:
            return cf_connecting_ip.strip()
        x_forwarded_for = request.headers.get("x-forwarded-for")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
    return peer_ip


class AuthRateLimiter:
    """Sliding-window IP rate limiter with lockout penalty for failed authentications."""

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: float = 600.0,
        lockout_seconds: float = 900.0,
    ) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._lockouts: dict[str, float] = {}
        self._failures: dict[str, list[float]] = {}
        self._dcr_counts: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def is_locked_out(self, ip: str) -> tuple[bool, int]:
        now = time.time()
        with self._lock:
            self._cleanup_expired(now)
            if ip in self._lockouts:
                unlock_at = self._lockouts[ip]
                if now < unlock_at:
                    return True, int(unlock_at - now)
                else:
                    del self._lockouts[ip]
                    self._failures.pop(ip, None)
            return False, 0

    def record_failure(self, ip: str) -> tuple[bool, int, int]:
        now = time.time()
        with self._lock:
            self._cleanup_expired(now)
            attempts = self._failures.setdefault(ip, [])
            attempts = [t for t in attempts if now - t < self.window_seconds]
            attempts.append(now)
            self._failures[ip] = attempts

            if len(attempts) >= self.max_attempts:
                self._lockouts[ip] = now + self.lockout_seconds
                return True, int(self.lockout_seconds), 0
            return False, 0, max(0, self.max_attempts - len(attempts))

    def record_success(self, ip: str) -> None:
        now = time.time()
        with self._lock:
            self._failures.pop(ip, None)
            self._lockouts.pop(ip, None)
            self._cleanup_expired(now)

    def check_dcr_rate_limit(self, ip: str, max_dcr_per_hour: int = 15) -> bool:
        now = time.time()
        with self._lock:
            self._cleanup_expired(now)
            records = self._dcr_counts.setdefault(ip, [])
            records = [t for t in records if now - t < 3600.0]
            if len(records) >= max_dcr_per_hour:
                self._dcr_counts[ip] = records
                return False
            records.append(now)
            self._dcr_counts[ip] = records
            return True

    def _cleanup_expired(self, now: float) -> None:
        """Prune expired lockouts, failure records, and DCR counters to bound memory."""
        expired_locks = [ip for ip, unlock in self._lockouts.items() if now >= unlock]
        for ip in expired_locks:
            del self._lockouts[ip]

        expired_fails = [
            ip for ip, timestamps in self._failures.items()
            if not timestamps or now - timestamps[-1] >= self.window_seconds
        ]
        for ip in expired_fails:
            del self._failures[ip]

        expired_dcr = [
            ip for ip, timestamps in self._dcr_counts.items()
            if not timestamps or now - timestamps[-1] >= 3600.0
        ]
        for ip in expired_dcr:
            del self._dcr_counts[ip]

        if len(self._failures) > 5000:
            for ip in list(self._failures.keys())[:1000]:
                del self._failures[ip]
        if len(self._lockouts) > 5000:
            for ip in list(self._lockouts.keys())[:1000]:
                del self._lockouts[ip]
        if len(self._dcr_counts) > 5000:
            for ip in list(self._dcr_counts.keys())[:1000]:
                del self._dcr_counts[ip]



def get_oauth_scopes(
    custom_scopes: list[str] | None = None,
    env_cfg: Any = None,
) -> list[str]:
    """Resolve supported OAuth scopes with custom, config, and environment fallbacks."""
    if custom_scopes:
        return list(custom_scopes)
    if env_cfg and getattr(env_cfg, "oauth_scopes", None):
        return list(env_cfg.oauth_scopes)
    env_scopes = os.getenv("MCP_OAUTH_SCOPES", "").strip()
    if env_scopes:
        return [s.strip() for s in env_scopes.split(",") if s.strip()]
    return list(DEFAULT_OAUTH_SCOPES)


def get_oauth_issuer(request: Request, custom_issuer: str | None = None, env_cfg: Any = None) -> str:
    """Resolve OAuth authorization server issuer URL from custom argument, config, env or request."""
    if custom_issuer and custom_issuer.strip():
        ci = custom_issuer.strip()
        return ci if ci.startswith(("http://", "https://")) else f"https://{ci}"
    configured_issuer = (getattr(env_cfg, "oauth_issuer", None) if env_cfg else None) or os.getenv("MCP_OAUTH_ISSUER", "").strip()
    if configured_issuer:
        return (
            configured_issuer
            if configured_issuer.startswith(("http://", "https://"))
            else f"https://{configured_issuer}"
        )
    auth0_domain = os.getenv("AUTH0_DOMAIN", "").replace("https://", "").rstrip("/")
    if auth0_domain:
        return f"https://{auth0_domain}"
    return get_server_public_url(request, env_cfg=env_cfg)


class LocalOAuthServer:
    """Embedded OAuth 2.1 server with native SQLite persistence, DCR, and PKCE verification."""

    def __init__(
        self,
        admin_password: str | None = None,
        db_path: Path | str | None = None,
        rate_limiter: AuthRateLimiter | None = None,
        max_auth_attempts: int | None = None,
        auth_lockout_secs: float | None = None,
        allowed_redirect_uris: list[str] | None = None,
        strict_client: bool | None = None,
        allow_plain_pkce: bool | None = None,
        require_pkce: bool | None = None,
        trust_proxy_headers: bool | None = None,
        preset_client_id: str | None = None,
        preset_client_name: str | None = None,
        config: Any = None,
    ) -> None:
        self.config = config
        self.custom_scopes: list[str] | None = getattr(config, "oauth_scopes", None) if config else None
        if admin_password is not None:
            self.admin_password = admin_password
        elif config and getattr(config, "api_key", None) is not None:
            self.admin_password = config.api_key
        else:
            self.admin_password = os.getenv("MCP_API_KEY", "")

        if db_path:
            self.db_path = str(db_path)
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        elif config and getattr(config, "db_path", None):
            self.db_path = str(config.db_path)
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        else:
            rdir = getattr(config, "runtime_dir", ".runtime") if config else ".runtime"
            runtime_dir = get_runtime_dir(runtime_dir_name=rdir)
            self.db_path = str(runtime_dir / "oauth_store.db")

        if rate_limiter:
            self.rate_limiter = rate_limiter
        else:
            attempts = (
                max_auth_attempts
                if max_auth_attempts is not None
                else (getattr(config, "auth_max_attempts", None) or int(os.getenv("MCP_AUTH_MAX_ATTEMPTS", "5")))
            )
            lockout = (
                auth_lockout_secs
                if auth_lockout_secs is not None
                else (getattr(config, "auth_lockout_secs", None) or float(os.getenv("MCP_AUTH_LOCKOUT_SECS", "900")))
            )
            self.rate_limiter = AuthRateLimiter(max_attempts=attempts, lockout_seconds=lockout)

        # Resolve configuration with precedence: explicit arg -> config -> env var default
        if allowed_redirect_uris is not None:
            self.allowed_redirect_uris = list(allowed_redirect_uris)
        elif config and getattr(config, "allowed_redirect_uris", None) is not None:
            self.allowed_redirect_uris = list(config.allowed_redirect_uris)
        else:
            self.allowed_redirect_uris = get_allowed_redirect_uris()

        if strict_client is not None:
            self.strict_client = strict_client
        elif config and getattr(config, "oauth_strict_client", None) is not None:
            self.strict_client = config.oauth_strict_client
        else:
            self.strict_client = os.getenv("MCP_OAUTH_STRICT_CLIENT", "1").strip().lower() not in ("0", "false", "no")

        if allow_plain_pkce is not None:
            self.allow_plain_pkce = allow_plain_pkce
        elif config and getattr(config, "oauth_allow_plain_pkce", None) is not None:
            self.allow_plain_pkce = config.oauth_allow_plain_pkce
        else:
            self.allow_plain_pkce = os.getenv("MCP_OAUTH_ALLOW_PLAIN_PKCE", "0").strip().lower() in ("1", "true", "yes")

        if require_pkce is not None:
            self.require_pkce = require_pkce
        elif config and getattr(config, "oauth_require_pkce", None) is not None:
            self.require_pkce = config.oauth_require_pkce
        else:
            self.require_pkce = os.getenv("MCP_OAUTH_REQUIRE_PKCE", "1").strip().lower() not in ("0", "false", "no")

        if trust_proxy_headers is not None:
            self.trust_proxy_headers = trust_proxy_headers
        elif config and getattr(config, "trust_proxy_headers", None) is not None:
            self.trust_proxy_headers = config.trust_proxy_headers
        else:
            t_raw = os.getenv("MCP_TRUST_PROXY_HEADERS", "").strip().lower()
            self.trust_proxy_headers = True if t_raw in ("1", "true", "yes", "always") else (False if t_raw in ("0", "false", "no", "never") else None)

        if preset_client_id is not None:
            self.preset_client_id = preset_client_id
        elif config and getattr(config, "preset_client_id", None) is not None:
            self.preset_client_id = config.preset_client_id
        else:
            self.preset_client_id = os.getenv("MCP_PRESET_CLIENT_ID", "chatgpt").strip() or "chatgpt"

        if preset_client_name is not None:
            self.preset_client_name = preset_client_name
        elif config and getattr(config, "preset_client_name", None) is not None:
            self.preset_client_name = config.preset_client_name
        else:
            self.preset_client_name = os.getenv("MCP_PRESET_CLIENT_NAME", "ChatGPT Pre-registered").strip()

        self._token_cache: dict[str, float] = {}
        self._cache_lock = threading.Lock()
        self.custom_consent_renderer: Callable[..., str] | None = None
        self._init_db()

    def is_uri_allowed_for_client(
        self, client_id: str, redirect_uri: str, registered_client: dict[str, Any] | None = None
    ) -> bool:
        return is_uri_allowed_for_client(
            client_id, redirect_uri, registered_client=registered_client, oauth_server=self
        )

    def verify_pkce(self, code_verifier: str, code_challenge: str, method: str = "S256") -> bool:
        return verify_pkce(
            code_verifier,
            code_challenge,
            method=method,
            allow_plain=self.allow_plain_pkce,
            env_cfg=self.config,
        )

    def is_trusted_proxy(self, ip_str: str) -> bool:
        return is_trusted_proxy(ip_str, trust_override=self.trust_proxy_headers, env_cfg=self.config)

    def get_client_ip(self, request: Request) -> str:
        return get_client_ip(request, trust_override=self.trust_proxy_headers, env_cfg=self.config)

    def get_server_public_url(self, request: Request) -> str:
        return get_server_public_url(request, trust_override=self.trust_proxy_headers, env_cfg=self.config)

    def set_consent_template_renderer(self, renderer: Callable[..., str]) -> None:
        """Register a custom HTML consent template renderer callback."""
        self.custom_consent_renderer = renderer

    @contextmanager
    def _db_conn(self):
        """Context manager yielding SQLite connection with auto-commit and guaranteed close."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA busy_timeout=5000;")
        except Exception:
            pass
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._db_conn() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS oauth_clients (
                client_id TEXT PRIMARY KEY,
                client_secret TEXT,
                client_name TEXT,
                redirect_uris TEXT,
                grant_types TEXT,
                response_types TEXT,
                created_at REAL
            );
            CREATE TABLE IF NOT EXISTS oauth_tokens (
                access_token TEXT PRIMARY KEY,
                token_type TEXT,
                expires_in INTEGER,
                expires_at REAL,
                created_at REAL,
                scope TEXT,
                client_id TEXT
            );
            CREATE TABLE IF NOT EXISTS oauth_codes (
                code TEXT PRIMARY KEY,
                client_id TEXT,
                redirect_uri TEXT,
                code_challenge TEXT,
                code_challenge_method TEXT,
                scope TEXT,
                expires_at REAL,
                created_at REAL
            );
            CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON oauth_tokens(expires_at);
            CREATE INDEX IF NOT EXISTS idx_codes_expires_at ON oauth_codes(expires_at);
            """)

            now = time.time()
            conn.execute("DELETE FROM oauth_codes WHERE expires_at < ?", (now,))
            conn.execute("DELETE FROM oauth_tokens WHERE expires_at < ?", (now,))

            preset_client_id = self.preset_client_id
            preset_client_name = self.preset_client_name
            conn.execute("""
            INSERT OR IGNORE INTO oauth_clients (client_id, client_secret, client_name, redirect_uris, grant_types, response_types, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                preset_client_id,
                None,
                preset_client_name,
                "[]",
                '["authorization_code", "refresh_token"]',
                '["code"]',
                now,
            ))
            # Clear plaintext passwords from preset client record
            conn.execute("UPDATE oauth_clients SET client_secret = NULL WHERE client_id = ?", (preset_client_id,))

    def register_client(self, metadata: dict[str, Any]) -> dict[str, Any]:
        """RFC 7591 Dynamic Client Registration with automatic storage in SQLite and URI validation."""
        raw_uris = metadata.get("redirect_uris", [])
        validated_uris: list[str] = []
        if isinstance(raw_uris, list):
            for u in raw_uris:
                if isinstance(u, str):
                    is_ok, err_desc = validate_redirect_uri(u)
                    if not is_ok:
                        raise ValueError(f"Invalid redirect_uri: {err_desc}")
                    validated_uris.append(u)
                else:
                    raise ValueError("All redirect_uris elements must be strings")
        elif raw_uris:
            raise ValueError("redirect_uris must be a list of URI strings")

        raw_name = str(metadata.get("client_name", "OAuth Client")).strip()
        client_name = raw_name[:256] if raw_name else "OAuth Client"

        client_id = f"mcp_client_{secrets.token_urlsafe(12)}"
        client_secret = f"mcp_sec_{secrets.token_urlsafe(24)}"
        record = {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_name": client_name,
            "redirect_uris": validated_uris,
            "grant_types": metadata.get("grant_types", ["authorization_code", "refresh_token"]),
            "response_types": metadata.get("response_types", ["code"]),
            "created_at": time.time(),
        }
        with self._db_conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM oauth_clients").fetchone()[0]
            if total >= 200:
                preset_client_id = (self.preset_client_id or os.getenv("MCP_PRESET_CLIENT_ID", "chatgpt")).strip() or "chatgpt"
                protected = tuple(set(["chatgpt", "admin", preset_client_id]))
                placeholders = ",".join("?" for _ in protected)
                conn.execute(f"""
                DELETE FROM oauth_clients WHERE client_id NOT IN ({placeholders})
                AND client_id IN (
                    SELECT client_id FROM oauth_clients WHERE client_id NOT IN ({placeholders}) ORDER BY created_at ASC LIMIT 20
                )
                """, protected + protected)

            conn.execute("""
            INSERT INTO oauth_clients (client_id, client_secret, client_name, redirect_uris, grant_types, response_types, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                client_id,
                client_secret,
                record["client_name"],
                json.dumps(record["redirect_uris"]),
                json.dumps(record["grant_types"]),
                json.dumps(record["response_types"]),
                record["created_at"],
            ))
        return record

    def get_client(self, client_id: str) -> dict[str, Any] | None:
        """Retrieve registered client record from SQLite."""
        if not client_id:
            return None
        with self._db_conn() as conn:
            row = conn.execute("SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,)).fetchone()
            if row:
                d = dict(row)
                for list_field in ("redirect_uris", "grant_types", "response_types"):
                    val = d.get(list_field)
                    if isinstance(val, str):
                        try:
                            d[list_field] = json.loads(val)
                        except Exception:
                            d[list_field] = []
                    elif not isinstance(val, list):
                        d[list_field] = []
                return d
        return None

    def create_auth_code(
        self,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str = "S256",
        scope: str = "",
    ) -> str:
        """Issue an authorization code stored safely in SQLite."""
        code = f"auth_code_{secrets.token_urlsafe(24)}"
        now = time.time()
        expires_at = now + 600  # 10 minutes
        with self._db_conn() as conn:
            conn.execute("""
            INSERT INTO oauth_codes (code, client_id, redirect_uri, code_challenge, code_challenge_method, scope, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (code, client_id, redirect_uri, code_challenge, code_challenge_method, scope, expires_at, now))
        return code

    def exchange_code_for_token(
        self,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> dict[str, Any]:
        """Exchange authorization code and PKCE verifier for a persistent access token."""
        now = time.time()
        with self._db_conn() as conn:
            row = conn.execute("SELECT * FROM oauth_codes WHERE code = ?", (code,)).fetchone()
            if not row:
                raise ValueError("Invalid or expired authorization code")
            auth_data = dict(row)

            if now > auth_data["expires_at"]:
                conn.execute("DELETE FROM oauth_codes WHERE code = ?", (code,))
                raise ValueError("Authorization code has expired")

            if not client_id:
                raise ValueError("client_id is required")
            expected_cid = auth_data.get("client_id")
            if expected_cid and client_id != expected_cid:
                raise ValueError("client_id mismatch")

            expected_redirect_uri = auth_data.get("redirect_uri")
            if expected_redirect_uri:
                if not redirect_uri or redirect_uri != expected_redirect_uri:
                    raise ValueError("redirect_uri mismatch")

            challenge = auth_data.get("code_challenge")
            method = auth_data.get("code_challenge_method", "S256")
            strict_pkce = self.require_pkce
            if challenge:
                if not code_verifier:
                    raise ValueError("code_verifier is required")
                if not verify_pkce(code_verifier, challenge, method, allow_plain=self.allow_plain_pkce, env_cfg=self.config):
                    raise ValueError("PKCE code verification failed")
            elif strict_pkce:
                raise ValueError("PKCE code challenge is required")

            # Invalidate used code
            conn.execute("DELETE FROM oauth_codes WHERE code = ?", (code,))

            access_token = f"mcp_tok_{secrets.token_urlsafe(32)}"
            expires_in = 86400 * 30  # 30 days
            expires_at = now + expires_in
            scope = auth_data.get("scope") or "mcp:read mcp:write"

            conn.execute("""
            INSERT INTO oauth_tokens (access_token, token_type, expires_in, expires_at, created_at, scope, client_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (access_token, "Bearer", expires_in, expires_at, now, scope, auth_data["client_id"]))

            with self._cache_lock:
                self._clean_token_cache_if_needed(now)
                self._token_cache[access_token] = expires_at

            return {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": expires_in,
                "created_at": now,
                "scope": scope,
                "client_id": auth_data["client_id"],
            }

    def _clean_token_cache_if_needed(self, now: float) -> None:
        """Evict expired or excess tokens to avoid unbounded in-memory cache growth."""
        if len(self._token_cache) > 2000:
            expired = [t for t, exp in self._token_cache.items() if now >= exp]
            for t in expired:
                self._token_cache.pop(t, None)
            if len(self._token_cache) > 2000:
                for t in list(self._token_cache.keys())[:500]:
                    self._token_cache.pop(t, None)

    def is_token_valid(self, token: str) -> bool:
        """Check whether an issued access token or static admin password is valid."""
        if not token:
            return False
        if self.admin_password and secrets.compare_digest(token, self.admin_password):
            return True
        now = time.time()
        with self._cache_lock:
            self._clean_token_cache_if_needed(now)
            cached_exp = self._token_cache.get(token)
            if cached_exp is not None:
                if now < cached_exp:
                    return True
                else:
                    self._token_cache.pop(token, None)

        with self._db_conn() as conn:
            row = conn.execute("SELECT expires_at FROM oauth_tokens WHERE access_token = ?", (token,)).fetchone()
            if row:
                if now < row["expires_at"]:
                    with self._cache_lock:
                        self._token_cache[token] = row["expires_at"]
                    return True
                else:
                    conn.execute("DELETE FROM oauth_tokens WHERE access_token = ?", (token,))
                    with self._cache_lock:
                        self._token_cache.pop(token, None)
        return False


def get_server_public_url(
    request: Request,
    trust_override: bool | None = None,
    env_cfg: Any = None,
) -> str:
    """Determine public base URL honoring reverse proxy headers only from trusted proxies."""
    override = (getattr(env_cfg, "public_base_url", None) if env_cfg else None) or os.getenv("PUBLIC_BASE_URL", "").strip()
    if override:
        return override.rstrip("/")

    client = getattr(request, "client", None)
    host_val = getattr(client, "host", None) if client else None
    peer_ip = host_val if isinstance(host_val, str) else "127.0.0.1"

    if is_trusted_proxy(peer_ip, trust_override=trust_override, env_cfg=env_cfg):
        forwarded_proto = request.headers.get("x-forwarded-proto") or getattr(request.url, "scheme", "http")
        forwarded_host = (
            request.headers.get("x-forwarded-host")
            or request.headers.get("host")
            or getattr(request.url, "netloc", "127.0.0.1")
        )
        raw_host = forwarded_host.split(",")[0].strip()
    else:
        raw_host = getattr(request.url, "netloc", "127.0.0.1")
        forwarded_proto = getattr(request.url, "scheme", "http")

    sanitized_host = "".join(c for c in raw_host if c.isalnum() or c in ".-:[]")
    if not sanitized_host:
        sanitized_host = "127.0.0.1"

    return f"{forwarded_proto}://{sanitized_host}".rstrip("/")


async def oauth_protected_resource_endpoint(
    request: Request,
    custom_scopes: list[str] | None = None,
    custom_issuer: str | None = None,
    oauth_server: LocalOAuthServer | None = None,
    env_cfg: Any = None,
) -> Response:
    """RFC 9728 OAuth Protected Resource Metadata document for ChatGPT and AI Agents."""
    eff_env = env_cfg or getattr(oauth_server, "config", None)
    eff_trust = getattr(oauth_server, "trust_proxy_headers", None)
    public_url = get_server_public_url(request, trust_override=eff_trust, env_cfg=eff_env)
    issuer = get_oauth_issuer(request, custom_issuer=custom_issuer, env_cfg=eff_env)
    scopes = get_oauth_scopes(custom_scopes, env_cfg=eff_env)

    req_resource = request.query_params.get("resource")
    if req_resource:
        resource_uri = req_resource
    elif request.url.path.rstrip("/").endswith("/mcp"):
        resource_uri = f"{public_url}/mcp"
    else:
        resource_uri = f"{public_url}/mcp"

    metadata = {
        "resource": resource_uri,
        "authorization_servers": [issuer],
        "scopes_supported": scopes,
        "resource_documentation": f"{public_url}/",
    }
    return JSONResponse(metadata, headers={"Access-Control-Allow-Origin": "*"})


async def oauth_authorization_server_metadata_endpoint(
    request: Request,
    custom_scopes: list[str] | None = None,
    custom_issuer: str | None = None,
    allow_plain_pkce: bool | None = None,
    oauth_server: LocalOAuthServer | None = None,
    env_cfg: Any = None,
) -> Response:
    """RFC 8414 OAuth 2.0 Authorization Server Metadata document for ChatGPT and AI Agents."""
    eff_env = env_cfg or getattr(oauth_server, "config", None)
    eff_trust = getattr(oauth_server, "trust_proxy_headers", None)
    public_url = get_server_public_url(request, trust_override=eff_trust, env_cfg=eff_env)
    issuer = get_oauth_issuer(request, custom_issuer=custom_issuer, env_cfg=eff_env)
    scopes = get_oauth_scopes(custom_scopes, env_cfg=eff_env)

    eff_plain = (
        allow_plain_pkce
        if allow_plain_pkce is not None
        else (
            getattr(oauth_server, "allow_plain_pkce", None)
            if oauth_server is not None
            else (
                getattr(eff_env, "oauth_allow_plain_pkce", None)
                if eff_env is not None
                else os.getenv("MCP_OAUTH_ALLOW_PLAIN_PKCE", "0").strip().lower() in ("1", "true", "yes")
            )
        )
    )
    code_challenge_methods = ["S256", "plain"] if eff_plain else ["S256"]

    metadata = {
        "issuer": issuer,
        "authorization_endpoint": f"{public_url}/oauth/authorize",
        "token_endpoint": f"{public_url}/oauth/token",
        "registration_endpoint": f"{public_url}/oauth/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": code_challenge_methods,
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": scopes,
        "subject_types_supported": ["public"],
    }
    return JSONResponse(metadata, headers={"Access-Control-Allow-Origin": "*"})


async def oauth_jwks_endpoint(request: Request) -> Response:
    """JWKS endpoint returning empty or public keys for OIDC validation."""
    return JSONResponse({"keys": []}, headers={"Access-Control-Allow-Origin": "*"})


async def oauth_register_endpoint(request: Request, oauth_server: LocalOAuthServer) -> Response:
    """RFC 7591 Dynamic Client Registration endpoint for ChatGPT with rate limiting and payload validation."""
    client_ip = get_client_ip(request, trust_override=oauth_server.trust_proxy_headers)
    if not oauth_server.rate_limiter.check_dcr_rate_limit(client_ip):
        return JSONResponse(
            {"error": "rate_limit_exceeded", "error_description": "Too many client registration requests. Please wait."},
            status_code=429,
            headers={"Access-Control-Allow-Origin": "*", "Retry-After": "3600"},
        )

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > 65536:
                return JSONResponse(
                    {"error": "invalid_request", "error_description": "Request payload exceeds 64KB limit"},
                    status_code=413,
                    headers={"Access-Control-Allow-Origin": "*"},
                )
        except ValueError:
            pass

    try:
        body_chunks: list[bytes] = []
        total_bytes = 0
        async for chunk in request.stream():
            total_bytes += len(chunk)
            if total_bytes > 65536:
                return JSONResponse(
                    {"error": "invalid_request", "error_description": "Request payload exceeds 64KB limit"},
                    status_code=413,
                    headers={"Access-Control-Allow-Origin": "*"},
                )
            body_chunks.append(chunk)
        body_bytes = b"".join(body_chunks)
        body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        if not isinstance(body, dict):
            body = {}
    except Exception:
        body = {}

    try:
        client_info = oauth_server.register_client(body)
    except ValueError as e:
        return JSONResponse(
            {"error": "invalid_client_metadata", "error_description": str(e)},
            status_code=400,
            headers={"Access-Control-Allow-Origin": "*"},
        )

    return JSONResponse(client_info, status_code=201, headers={"Access-Control-Allow-Origin": "*"})


_RENDERER_KIND_CACHE: dict[Any, str] = {}


def _get_renderer_kind(renderer: Callable[..., str]) -> str:
    """Inspect and cache custom consent template renderer parameter profile."""
    if renderer not in _RENDERER_KIND_CACHE:
        import inspect
        sig = inspect.signature(renderer)
        params = [
            p for p in sig.parameters.values()
            if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]
        if len(params) == 1:
            _RENDERER_KIND_CACHE[renderer] = "dict"
        elif "service_title" in sig.parameters or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()):
            _RENDERER_KIND_CACHE[renderer] = "kwarg"
        else:
            _RENDERER_KIND_CACHE[renderer] = "positional"
    return _RENDERER_KIND_CACHE[renderer]


async def oauth_authorize_endpoint(
    request: Request,
    oauth_server: LocalOAuthServer,
    service_title: str = "MCP Service",
    consent_renderer: Callable[..., str] | None = None,
) -> Response:
    """Handle OAuth 2.1 authorization consent page and code generation with brute-force defense."""
    effective_renderer = consent_renderer or oauth_server.custom_consent_renderer

    def render_page(err: str, cid: str, ruri: str, sc: str, st: str, cc: str, cm: str) -> str:
        if effective_renderer:
            kind = _get_renderer_kind(effective_renderer)
            if kind == "dict":
                ctx = {
                    "error_msg": err,
                    "client_id": cid,
                    "redirect_uri": ruri,
                    "scope": sc,
                    "state": st,
                    "code_challenge": cc,
                    "code_challenge_method": cm,
                    "service_title": service_title,
                }
                return effective_renderer(ctx)
            elif kind == "kwarg":
                return effective_renderer(err, cid, ruri, sc, st, cc, cm, service_title=service_title)
            else:
                return effective_renderer(err, cid, ruri, sc, st, cc, cm)
        return _render_consent_html(err, cid, ruri, sc, st, cc, cm, service_title=service_title)

    params = request.query_params
    response_type = params.get("response_type", "code")
    client_id = params.get("client_id", "").strip()
    redirect_uri = params.get("redirect_uri", "").strip()
    scope = params.get("scope", "")
    state = params.get("state", "")
    code_challenge = params.get("code_challenge", "").strip()
    code_challenge_method = params.get("code_challenge_method", "S256").strip()

    strict_pkce = oauth_server.require_pkce
    allow_plain = oauth_server.allow_plain_pkce
    allowed_methods = ("S256", "plain") if allow_plain else ("S256",)

    client_ip = get_client_ip(request, trust_override=oauth_server.trust_proxy_headers)
    is_locked, remaining_seconds = oauth_server.rate_limiter.is_locked_out(client_ip)
    if is_locked:
        err_msg = f"❌ 连续输入错误密码过多，IP 已被安全锁定。请在 {remaining_seconds} 秒后再试！"
        html_page = render_page(
            err_msg,
            client_id,
            redirect_uri,
            scope,
            state,
            code_challenge,
            code_challenge_method,
        )
        return HTMLResponse(html_page, status_code=429, headers={"Retry-After": str(remaining_seconds)})

    if request.method == "POST":
        form = await request.form()
        password = str(form.get("password", "")).strip()
        f_client_id = str(form.get("client_id", client_id)).strip()
        f_redirect_uri = str(form.get("redirect_uri", redirect_uri)).strip()
        f_response_type = str(form.get("response_type", response_type)).strip()
        f_scope = str(form.get("scope", scope))
        f_state = str(form.get("state", state))
        f_challenge = str(form.get("code_challenge", code_challenge)).strip()
        f_method = str(form.get("code_challenge_method", code_challenge_method)).strip()

        if f_response_type != "code":
            return JSONResponse(
                {"error": "unsupported_response_type", "error_description": "Only response_type=code is supported"},
                status_code=400,
                headers={"Access-Control-Allow-Origin": "*"},
            )

        if not f_client_id:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "client_id is required"},
                status_code=400,
                headers={"Access-Control-Allow-Origin": "*"},
            )

        if not f_redirect_uri:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Missing redirect_uri parameter"},
                status_code=400,
                headers={"Access-Control-Allow-Origin": "*"},
            )

        is_valid_uri, uri_err = validate_redirect_uri(f_redirect_uri)
        if not is_valid_uri:
            return JSONResponse(
                {"error": "invalid_request", "error_description": uri_err},
                status_code=400,
                headers={"Access-Control-Allow-Origin": "*"},
            )

        post_reg_client = oauth_server.get_client(f_client_id)
        if not is_uri_allowed_for_client(f_client_id, f_redirect_uri, post_reg_client, oauth_server=oauth_server):
            return JSONResponse(
                {"error": "invalid_request", "error_description": "redirect_uri mismatch for registered client"},
                status_code=400,
                headers={"Access-Control-Allow-Origin": "*"},
            )

        if strict_pkce and not f_challenge:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "code_challenge is required (PKCE S256)"},
                status_code=400,
                headers={"Access-Control-Allow-Origin": "*"},
            )

        if f_challenge and f_method not in allowed_methods:
            return JSONResponse(
                {"error": "invalid_request", "error_description": f"Unsupported code_challenge_method: {f_method}. S256 required."},
                status_code=400,
                headers={"Access-Control-Allow-Origin": "*"},
            )

        if oauth_server.admin_password and not secrets.compare_digest(password, oauth_server.admin_password):
            is_locked, lockout_secs, remaining_attempts = oauth_server.rate_limiter.record_failure(client_ip)
            if is_locked:
                err_text = f"❌ 密码错误次数超限！IP 已触发锁定保护，请在 {lockout_secs} 秒后重试。"
                status_code = 429
                headers = {"Retry-After": str(lockout_secs)}
            else:
                err_text = f"❌ 访问密码错误！还可尝试 {remaining_attempts} 次。"
                status_code = 401
                headers = {}

            error_html = render_page(
                err_text,
                f_client_id,
                f_redirect_uri,
                f_scope,
                f_state,
                f_challenge,
                f_method,
            )
            return HTMLResponse(error_html, status_code=status_code, headers=headers)

        oauth_server.rate_limiter.record_success(client_ip)

        # Validate/filter scope according to allowed scopes if scope is specified
        supported_scopes = get_oauth_scopes(oauth_server.custom_scopes, env_cfg=oauth_server.config)
        supported_set = set(supported_scopes)
        if f_scope:
            req_scopes = [s.strip() for s in f_scope.replace(",", " ").split() if s.strip()]
            valid_scopes = [s for s in req_scopes if s in supported_set]
            eff_scope = " ".join(valid_scopes) if valid_scopes else " ".join(supported_scopes)
        else:
            eff_scope = " ".join(supported_scopes)

        code = oauth_server.create_auth_code(
            client_id=f_client_id,
            redirect_uri=f_redirect_uri,
            code_challenge=f_challenge,
            code_challenge_method=f_method,
            scope=eff_scope,
        )

        query_parts = {"code": code}
        if f_state:
            query_parts["state"] = f_state

        sep = "&" if "?" in f_redirect_uri else "?"
        callback_url = f"{f_redirect_uri}{sep}{urlencode(query_parts)}"
        return RedirectResponse(callback_url, status_code=302)

    # GET request: Validate client_id, redirect_uri, response_type and PKCE upfront before showing consent page
    if response_type != "code":
        return JSONResponse(
            {"error": "unsupported_response_type", "error_description": "Only response_type=code is supported"},
            status_code=400,
            headers={"Access-Control-Allow-Origin": "*"},
        )

    if not client_id:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "client_id is required"},
            status_code=400,
            headers={"Access-Control-Allow-Origin": "*"},
        )

    if not redirect_uri:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Missing redirect_uri parameter"},
            status_code=400,
            headers={"Access-Control-Allow-Origin": "*"},
        )

    is_valid_uri, uri_err = validate_redirect_uri(redirect_uri)
    if not is_valid_uri:
        return JSONResponse(
            {"error": "invalid_request", "error_description": uri_err},
            status_code=400,
            headers={"Access-Control-Allow-Origin": "*"},
        )

    reg_client = oauth_server.get_client(client_id)
    if not is_uri_allowed_for_client(client_id, redirect_uri, reg_client, oauth_server=oauth_server):
        return JSONResponse(
            {"error": "invalid_request", "error_description": "redirect_uri mismatch for registered client"},
            status_code=400,
            headers={"Access-Control-Allow-Origin": "*"},
        )

    if strict_pkce and not code_challenge:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "code_challenge is required (PKCE S256)"},
            status_code=400,
            headers={"Access-Control-Allow-Origin": "*"},
        )

    if code_challenge and code_challenge_method not in allowed_methods:
        return JSONResponse(
            {"error": "invalid_request", "error_description": f"Unsupported code_challenge_method: {code_challenge_method}. S256 required."},
            status_code=400,
            headers={"Access-Control-Allow-Origin": "*"},
        )

    content = render_page(
        "",
        client_id,
        redirect_uri,
        scope,
        state,
        code_challenge,
        code_challenge_method,
    )
    return HTMLResponse(content)


async def oauth_token_endpoint(request: Request, oauth_server: LocalOAuthServer) -> Response:
    """RFC 6749 & RFC 7636 Token Endpoint with PKCE verification."""
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            data = await request.json()
            if not isinstance(data, dict):
                data = {}
        except Exception:
            data = {}
    else:
        form = await request.form()
        data = dict(form)

    grant_type = data.get("grant_type")
    code = data.get("code", "")
    client_id = data.get("client_id", "")
    redirect_uri = data.get("redirect_uri", "")
    code_verifier = data.get("code_verifier", "")

    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
            if ":" in decoded:
                client_id = decoded.split(":")[0]
        except Exception:
            pass

    if grant_type != "authorization_code":
        return JSONResponse(
            {"error": "unsupported_grant_type", "error_description": "Only authorization_code is supported"},
            status_code=400,
            headers={"Access-Control-Allow-Origin": "*"},
        )

    try:
        token_info = oauth_server.exchange_code_for_token(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )
        return JSONResponse(token_info, headers={"Access-Control-Allow-Origin": "*"})
    except ValueError as e:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": str(e)},
            status_code=400,
            headers={"Access-Control-Allow-Origin": "*"},
        )


def _render_consent_html(
    error_msg: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str,
    service_title: str = "MCP Service",
) -> str:
    """Render clean, responsive HTML consent page for MCP authorization."""
    err_block = f'<div style="color: #ef4444; background: #fee2e2; border: 1px solid #f87171; padding: 10px; border-radius: 6px; margin-bottom: 16px; font-size: 14px;">{html.escape(error_msg)}</div>' if error_msg else ""
    esc_title = html.escape(service_title)
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{esc_title} / 安全授权</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #f3f4f6;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            padding: 16px;
        }}
        .card {{
            background: #ffffff;
            border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.08);
            width: 100%;
            max-width: 440px;
            padding: 32px;
            box-sizing: border-box;
        }}
        h2 {{
            margin-top: 0;
            color: #111827;
            font-size: 22px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        p {{
            color: #4b5563;
            font-size: 14px;
            line-height: 1.5;
        }}
        .badge {{
            background: #e0f2fe;
            color: #0369a1;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }}
        label {{
            display: block;
            margin-bottom: 6px;
            font-size: 14px;
            color: #374151;
            font-weight: 500;
        }}
        input[type="password"] {{
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font-size: 15px;
            box-sizing: border-box;
            outline: none;
            transition: border-color 0.2s;
        }}
        input[type="password"]:focus {{
            border-color: #2563eb;
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15);
        }}
        button {{
            width: 100%;
            background: #10a37f;
            color: #ffffff;
            border: none;
            padding: 12px;
            border-radius: 6px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 20px;
            transition: background 0.2s;
        }}
        button:hover {{
            background: #0e8c6d;
        }}
        .footer {{
            margin-top: 20px;
            font-size: 12px;
            color: #9ca3af;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="card">
        <h2>🚀 {esc_title} 安全授权</h2>
        <p>客户端正在请求连接 <b>{esc_title}</b>，请验证安全访问密钥以完成授权绑定。</p>
        <p><span class="badge">安全隔离</span> 权限仅对经过授权的会话生效。</p>
        
        {err_block}
        
        <form method="POST">
            <input type="hidden" name="client_id" value="{html.escape(client_id)}">
            <input type="hidden" name="redirect_uri" value="{html.escape(redirect_uri)}">
            <input type="hidden" name="response_type" value="code">
            <input type="hidden" name="scope" value="{html.escape(scope)}">
            <input type="hidden" name="state" value="{html.escape(state)}">
            <input type="hidden" name="code_challenge" value="{html.escape(code_challenge)}">
            <input type="hidden" name="code_challenge_method" value="{html.escape(code_challenge_method)}">
            
            <label for="password">请输入安全访问密钥 (API Key):</label>
            <input type="password" id="password" name="password" required autofocus placeholder="输入控制台或 .env 中的访问密钥">
            
            <button type="submit">确认授权客户端访问</button>
        </form>
        
        <div class="footer">
            {esc_title} • RFC 9728 & OAuth 2.1
        </div>
    </div>
</body>
</html>"""
