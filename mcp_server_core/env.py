"""Generic MCP Server Environment & Deployment Configuration Module.

Independent of any domain-specific business logic, this module handles:
1. System runtime directory management (.runtime / .mcp_runtime).
2. Dynamic environment variable updates (.env persistence).
3. Generic deployment configuration loading (ports, hosts, Cloudflare tunnels, auth keys, SQLite paths).
"""
from __future__ import annotations

import os
import re
import secrets
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .constants import (
    DEFAULT_GLOBAL_ENV_FILE,
    DEFAULT_GLOBAL_MCP_DIR,
    DEFAULT_MCP_PORT,
    DEFAULT_OAUTH_SCOPES,
)
from .logging.config import LoggingConfig

OVERRIDE_ALIASES: dict[str, list[str]] = {
    "tunnel_token": ["CLOUDFLARE_TUNNEL_TOKEN", "MCP_TUNNEL_TOKEN", "tunnel_token"],
    "cloudflared_path": ["CLOUDFLARED_PATH", "CLOUDFLARED_BIN", "cloudflared_path", "cloudflared_bin"],
    "cloudflare_metrics_port": ["CLOUDFLARE_METRICS_PORT", "cloudflare_metrics_port", "metrics_port"],
    "metrics_port": ["CLOUDFLARE_METRICS_PORT", "cloudflare_metrics_port", "metrics_port"],
    "port": ["MCP_PORT", "port"],
    "host": ["MCP_HOST", "host"],
    "path": ["MCP_PATH", "path"],
    "api_key": ["MCP_API_KEY", "api_key"],
    "require_auth": ["MCP_REQUIRE_AUTH", "require_auth"],
    "allow_public_bind": ["MCP_ALLOW_PUBLIC_BIND", "allow_public_bind"],
    "tunnel": ["MCP_TUNNEL", "tunnel"],
    "portal_url": ["MCP_PORTAL_URL", "portal_url"],
    "upstream_url": ["MCP_UPSTREAM_URL", "upstream_url"],
    "allow_query_auth": ["MCP_ALLOW_QUERY_AUTH", "allow_query_auth"],
    "enable_public_oauth": ["MCP_ENABLE_PUBLIC_OAUTH", "enable_public_oauth"],
    "db_path": ["MCP_DB_PATH", "db_path"],
    "oauth_issuer": ["MCP_OAUTH_ISSUER", "oauth_issuer"],
    "oauth_scopes": ["MCP_OAUTH_SCOPES", "oauth_scopes"],
    "auth_max_attempts": ["MCP_AUTH_MAX_ATTEMPTS", "auth_max_attempts"],
    "auth_lockout_secs": ["MCP_AUTH_LOCKOUT_SECS", "auth_lockout_secs"],
    "service_name": ["MCP_SERVICE_NAME", "service_name"],
    "service_title": ["MCP_SERVICE_TITLE", "service_title"],
    "oauth_strict_pkce": ["MCP_OAUTH_STRICT_PKCE", "oauth_strict_pkce"],
    "log_dir": ["MCP_LOG_DIR", "log_dir", "dir"],
    "log_level": ["MCP_LOG_LEVEL", "log_level", "level"],
    "log_app_file": ["MCP_LOG_APP_FILE", "log_app_file", "app_filename"],
    "log_access_file": ["MCP_LOG_ACCESS_FILE", "log_access_file", "access_filename"],
    "log_error_file": ["MCP_LOG_ERROR_FILE", "log_error_file", "error_filename"],
}


def _parse_bool(value: Any, default: bool = False) -> bool:
    """Robustly parse boolean representations."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    str_val = str(value).strip().lower()
    if str_val in ("true", "1", "yes", "on", "y"):
        return True
    if str_val in ("false", "0", "no", "off", "n", ""):
        return False
    return default


def _parse_int(value: Any, default: int = 8788) -> int:
    """Safely parse integer representations with default fallback."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def get_global_mcp_dir() -> Path:
    """Return the global ~/.mcp configuration and cache directory."""
    custom = os.getenv("MCP_GLOBAL_DIR")
    if custom:
        return Path(custom).resolve()
    return DEFAULT_GLOBAL_MCP_DIR


def get_global_env_file() -> Path:
    """Return the global environment file path (defaults to ~/.mcp/.env)."""
    custom = os.getenv("MCP_GLOBAL_ENV")
    if custom:
        return Path(custom).resolve()
    if os.getenv("MCP_GLOBAL_DIR"):
        return get_global_mcp_dir() / ".env"
    return DEFAULT_GLOBAL_ENV_FILE


def parse_env_file(file_path: Path | str) -> dict[str, str]:
    """Parse key-value pairs from a .env file safely without mutating os.environ."""
    p = Path(file_path).resolve()
    if not p.is_file():
        return {}
    try:
        from dotenv import dotenv_values
        return {str(k): str(v) for k, v in dotenv_values(p).items() if v is not None}
    except Exception:
        vals: dict[str, str] = {}
        try:
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    vals[k.strip()] = v.strip().strip('"').strip("'")
        except Exception:
            pass
        return vals


def get_runtime_dir(base_dir: Path | None = None, runtime_dir_name: str | None = None) -> Path:
    """Get or create the centralized runtime directory for temporary/state files."""
    root = (base_dir or Path.cwd()).resolve()
    dir_name = runtime_dir_name or os.getenv("MCP_RUNTIME_DIR", ".runtime")
    runtime_dir = root / dir_name
    runtime_dir.mkdir(parents=True, exist_ok=True)
    return runtime_dir


def update_env_variable(key: str, value: str, env_path: Path | None = None) -> None:
    """Update or append an environment variable in the target .env file atomically (file-only)."""
    target = env_path or (Path.cwd() / ".env")
    lines = []
    found = False
    pattern = re.compile(rf"^(?:export\s+)?{re.escape(key)}\s*=", re.IGNORECASE)
    if target.exists():
        for line in target.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if pattern.match(stripped):
                lines.append(f"{key}={value}")
                found = True
            else:
                lines.append(line)
    if not found:
        lines.append(f"{key}={value}")

    # Atomic write via temporary file
    temp_target = target.with_suffix(f".tmp_{os.getpid()}_{time.time_ns()}")
    temp_target.parent.mkdir(parents=True, exist_ok=True)
    try:
        temp_target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        if target.exists():
            try:
                shutil.copymode(target, temp_target)
            except Exception:
                pass
        temp_target.replace(target)
    finally:
        if temp_target.exists():
            try:
                temp_target.unlink()
            except Exception:
                pass


def update_global_env_variable(key: str, value: str) -> None:
    """Update or append an environment variable in the global ~/.mcp/.env file."""
    update_env_variable(key, value, env_path=get_global_env_file())


def ensure_api_key(root_dir: Path | None = None, env_path: Path | None = None) -> str:
    """Explicitly ensure an API key exists, auto-generating and writing it to .env if absent."""
    root = (root_dir or Path.cwd()).resolve()
    target_env = env_path or (root / ".env")
    key = ""
    if target_env.exists():
        for line in target_env.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("MCP_API_KEY="):
                key = stripped.split("=", 1)[1].strip().strip('"').strip("'")
                break
    if not key:
        key = os.getenv("MCP_API_KEY", "").strip()
    if not key:
        key = f"sec_{secrets.token_urlsafe(16)}"
        try:
            update_env_variable("MCP_API_KEY", key, target_env)
        except Exception:
            pass
    return key


@dataclass
class DeploymentEnvConfig:
    """Generic MCP server deployment and runtime environment configuration (loaded from .env).
    
    This class manages purely infrastructure parameters (ports, hosts, Cloudflare tunnel tokens,
    API keys, and OAuth database paths) completely independent of any project business logic.
    """
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 8788
    path: str = "/mcp"
    require_auth: bool = True
    api_key: str = ""
    allow_public_bind: bool = True
    tunnel: bool = True
    tunnel_token: str = ""
    portal_url: str = ""
    upstream_url: str = ""
    allow_query_auth: bool = False
    enable_public_oauth: bool = False
    db_path: str = ""
    cloudflared_path: str = ""
    oauth_issuer: str = ""
    oauth_scopes: list[str] = field(default_factory=lambda: list(DEFAULT_OAUTH_SCOPES))
    auth_max_attempts: int = 5
    auth_lockout_secs: int = 900
    cloudflare_metrics_port: int = 20245
    service_name: str = "mcp_service"
    service_title: str | None = None
    cors_origins: list[str] = field(default_factory=lambda: ["*"])
    allowed_redirect_uris: list[str] = field(default_factory=list)
    trust_proxy_headers: bool = False
    oauth_strict_client: bool = True
    oauth_allow_plain_pkce: bool = False
    oauth_require_pkce: bool = True
    oauth_strict_pkce: bool = False
    preset_client_id: str | None = None
    preset_client_name: str | None = None
    runtime_dir: str = ".runtime"
    logging_config: LoggingConfig | None = None

    @property
    def display_title(self) -> str:
        """Return the resolved human-readable service title."""
        if self.service_title:
            return self.service_title
        return self.service_name.replace("_", " ").title()

    @classmethod
    def load(
        cls,
        base_dir: Path | None = None,
        overrides: dict[str, Any] | None = None,
        env_file: Path | None = None,
        auto_create_key: bool = False,
        global_env_file: Path | None = None,
    ) -> DeploymentEnvConfig:
        """Load deployment and runtime configuration from .env and environment variables.

        Pure configuration loader: does not mutate os.environ and does not write to disk
        unless auto_create_key is explicitly True. Supports cascading fallback to ~/.mcp/.env.
        """
        root = (base_dir or Path.cwd()).resolve()
        target_env = env_file or (root / ".env")
        resolved_global_env = Path(global_env_file).resolve() if global_env_file else get_global_env_file()

        # 1. Load global ~/.mcp/.env (if exists)
        global_vals: dict[str, str] = {}
        if resolved_global_env.is_file():
            global_vals = parse_env_file(resolved_global_env)

        # 2. Load project target .env (if exists)
        project_vals: dict[str, str] = {}
        if target_env.is_file():
            project_vals = parse_env_file(target_env)

        # Merge file values: non-empty project values take precedence;
        # empty project placeholders fall back to global values.
        file_vals: dict[str, str] = dict(global_vals)
        for k, v in project_vals.items():
            if str(v).strip():
                file_vals[k] = v
            elif k not in file_vals:
                file_vals[k] = v

        norm_overrides: dict[str, Any] = dict(overrides or {})
        for k, v in list(norm_overrides.items()):
            k_lower = k.lower()
            if k_lower in OVERRIDE_ALIASES:
                for alias in OVERRIDE_ALIASES[k_lower]:
                    norm_overrides.setdefault(alias, v)
                    norm_overrides.setdefault(alias.lower(), v)

        def _get(env_key: str, default: Any = None) -> Any:
            if env_key in norm_overrides:
                return norm_overrides[env_key]
            if env_key.lower() in norm_overrides:
                return norm_overrides[env_key.lower()]
            short = env_key.lower().replace("mcp_", "")
            if short in norm_overrides:
                return norm_overrides[short]
            # Project .env non-empty values take precedence over os.environ
            if env_key in project_vals and str(project_vals[env_key]).strip():
                return project_vals[env_key]
            # Shell/system environment variables take precedence over global ~/.mcp/.env
            if env_key in os.environ and str(os.environ[env_key]).strip():
                return os.environ[env_key]
            # Fallback to merged file_vals (global ~/.mcp/.env or project empty values)
            if env_key in file_vals:
                return file_vals[env_key]
            if env_key in os.environ:
                return os.environ[env_key]
            return default

        raw_rdir = _get("MCP_RUNTIME_DIR", ".runtime")
        resolved_rdir = str(raw_rdir).strip() if raw_rdir and str(raw_rdir).strip() else ".runtime"
        runtime_dir = get_runtime_dir(root, runtime_dir_name=resolved_rdir)

        is_auth_req = _parse_bool(
            _get("MCP_REQUIRE_AUTH", "true"),
            default=True,
        )
        resolved_api_key = str(_get("MCP_API_KEY", "")).strip()

        if auto_create_key and is_auth_req and not resolved_api_key:
            resolved_api_key = ensure_api_key(root, target_env)

        resolved_tunnel_token = str(
            _get("CLOUDFLARE_TUNNEL_TOKEN", _get("MCP_TUNNEL_TOKEN", ""))
        ).strip()

        raw_scopes = _get("MCP_OAUTH_SCOPES", "")
        if isinstance(raw_scopes, list):
            resolved_scopes = [str(s).strip() for s in raw_scopes if str(s).strip()]
        elif isinstance(raw_scopes, str) and raw_scopes.strip():
            resolved_scopes = [s.strip() for s in raw_scopes.split(",") if s.strip()]
        else:
            resolved_scopes = list(DEFAULT_OAUTH_SCOPES)

        raw_issuer = str(
            _get("MCP_OAUTH_ISSUER", _get("AUTH0_DOMAIN", ""))
        ).strip()

        raw_service_name = str(_get("MCP_SERVICE_NAME", "mcp_service")).strip()
        resolved_service_name = raw_service_name if raw_service_name else "mcp_service"

        raw_service_title = _get("MCP_SERVICE_TITLE", None)
        resolved_service_title = str(raw_service_title).strip() if raw_service_title is not None and str(raw_service_title).strip() else None

        raw_cors = _get("MCP_CORS_ORIGINS", "*")
        if isinstance(raw_cors, list):
            resolved_cors = [str(o).strip() for o in raw_cors if str(o).strip()]
        elif isinstance(raw_cors, str) and raw_cors.strip() and raw_cors.strip() != "*":
            resolved_cors = [o.strip() for o in raw_cors.split(",") if o.strip()]
        else:
            resolved_cors = ["*"]
        if not resolved_cors:
            resolved_cors = ["*"]

        raw_redirects = _get("MCP_ALLOWED_REDIRECT_URIS", "")
        if isinstance(raw_redirects, list):
            resolved_redirects = [str(u).strip() for u in raw_redirects if str(u).strip()]
        elif isinstance(raw_redirects, str) and raw_redirects.strip():
            resolved_redirects = [u.strip() for u in raw_redirects.split(",") if u.strip()]
        else:
            resolved_redirects = []

        resolved_trust_proxy = _parse_bool(_get("MCP_TRUST_PROXY_HEADERS", "0"), default=False)
        resolved_strict_client = _parse_bool(_get("MCP_OAUTH_STRICT_CLIENT", "1"), default=True)
        resolved_allow_plain = _parse_bool(_get("MCP_OAUTH_ALLOW_PLAIN_PKCE", "0"), default=False)
        resolved_req_pkce = _parse_bool(_get("MCP_OAUTH_REQUIRE_PKCE", "1"), default=True)
        resolved_strict_pkce = _parse_bool(_get("MCP_OAUTH_STRICT_PKCE", "0"), default=False)

        raw_preset_id = _get("MCP_PRESET_CLIENT_ID", None)
        resolved_preset_id = str(raw_preset_id).strip() if raw_preset_id is not None and str(raw_preset_id).strip() else None

        raw_preset_name = _get("MCP_PRESET_CLIENT_NAME", None)
        resolved_preset_name = str(raw_preset_name).strip() if raw_preset_name is not None and str(raw_preset_name).strip() else None

        # Resolve logging configuration
        logging_dict = overrides.get("logging") if overrides and isinstance(overrides.get("logging"), dict) else (overrides or {})
        resolved_logging = LoggingConfig.from_dict_and_env(
            base_dir=root,
            config_dict=logging_dict,
        )

        return cls(
            enabled=_parse_bool(_get("MCP_ENABLED", True), default=True),
            host=str(_get("MCP_HOST", "127.0.0.1")),
            port=_parse_int(_get("MCP_PORT", DEFAULT_MCP_PORT), default=DEFAULT_MCP_PORT),
            path=str(_get("MCP_PATH", "/mcp")),
            require_auth=is_auth_req,
            api_key=resolved_api_key,
            allow_public_bind=_parse_bool(_get("MCP_ALLOW_PUBLIC_BIND", True), default=True),
            tunnel=_parse_bool(_get("MCP_TUNNEL", "true"), default=True),
            tunnel_token=resolved_tunnel_token,
            portal_url=str(_get("MCP_PORTAL_URL", "")),
            upstream_url=str(_get("MCP_UPSTREAM_URL", "")),
            allow_query_auth=_parse_bool(_get("MCP_ALLOW_QUERY_AUTH", "false"), default=False),
            enable_public_oauth=_parse_bool(_get("MCP_ENABLE_PUBLIC_OAUTH", "false"), default=False),
            db_path=str(_get("MCP_DB_PATH", str(runtime_dir / "oauth_store.db"))),
            cloudflared_path=str(_get("CLOUDFLARED_PATH", _get("CLOUDFLARED_BIN", ""))).strip(),
            oauth_issuer=raw_issuer,
            oauth_scopes=resolved_scopes,
            auth_max_attempts=_parse_int(_get("MCP_AUTH_MAX_ATTEMPTS", 5), default=5),
            auth_lockout_secs=_parse_int(_get("MCP_AUTH_LOCKOUT_SECS", 900), default=900),
            cloudflare_metrics_port=_parse_int(
                _get("CLOUDFLARE_METRICS_PORT", 20245),
                default=20245,
            ),
            service_name=resolved_service_name,
            service_title=resolved_service_title,
            cors_origins=resolved_cors,
            allowed_redirect_uris=resolved_redirects,
            trust_proxy_headers=resolved_trust_proxy,
            oauth_strict_client=resolved_strict_client,
            oauth_allow_plain_pkce=resolved_allow_plain,
            oauth_require_pkce=resolved_req_pkce,
            oauth_strict_pkce=resolved_strict_pkce,
            preset_client_id=resolved_preset_id,
            preset_client_name=resolved_preset_name,
            runtime_dir=resolved_rdir,
            logging_config=resolved_logging,
        )
