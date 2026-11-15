"""Logging configuration data model and multi-tier precedence parser."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _parse_bool(val: Any, default: bool = True) -> bool:
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in ("1", "true", "yes", "on", "y"):
        return True
    if s in ("0", "false", "no", "off", "n", ""):
        return False
    return default


def _parse_int(val: Any, default: int) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


@dataclass
class LoggingConfig:
    """Universal logging system configuration definition (consumer-driven).

    Follows 'Convention over Configuration':
    - Safe in-project defaults (<project_root>/.runtime/logs/)
    - Full customizability for directory and individual file names
    - Precedence: Explicit kwargs > Environment variables > Config dict > Defaults
    """

    # Directory configuration: relative path automatically resolved against base_dir.
    # Strict project convergence to eliminate OS global directory pollution.
    log_dir: str = ".runtime/logs"

    # Filename configurations: individual streams can be freely renamed
    access_filename: str = "access.log"
    app_filename: str | None = None  # None resolves dynamically to f"{service_name}.log" or "app.log"
    error_filename: str = "error.log"

    # Rotation and logging level settings
    level: str = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    max_bytes: int = 10 * 1024 * 1024  # Default 10MB
    backup_count: int = 5  # Default 5 rotated backups
    enable_console: bool = True  # Mirror logs to console/stdout
    enable_trace_injection: bool = True  # Extract and bind CF-Ray / X-Request-ID

    # Sensitive key patterns to mask in arguments
    sensitive_keys: list[str] = field(
        default_factory=lambda: [
            "token",
            "key",
            "password",
            "secret",
            "auth",
            "credential",
            "api_key",
            "access_token",
            "private_key",
        ]
    )

    def resolve_log_dir(self, base_dir: Path | None = None) -> Path:
        """Resolve the absolute log directory and ensure it exists."""
        root = (base_dir or Path.cwd()).resolve()
        p = Path(self.log_dir)
        if not p.is_absolute():
            resolved = (root / p).resolve()
        else:
            resolved = p.resolve()
        resolved.mkdir(parents=True, exist_ok=True)
        return resolved

    def resolve_app_filename(self, service_name: str | None = None) -> str:
        """Resolve the app/tool log filename given an optional service name."""
        if self.app_filename:
            return self.app_filename
        if service_name and service_name.strip():
            clean_name = service_name.strip().replace(" ", "_").lower()
            return f"{clean_name}.log"
        return "app.log"

    @classmethod
    def from_dict_and_env(
        cls,
        base_dir: Path | None = None,
        config_dict: dict[str, Any] | None = None,
        **overrides: Any,
    ) -> LoggingConfig:
        """Construct LoggingConfig applying multi-tier precedence:

        1. Python API parameter overrides (kwargs)
        2. Environment variables (MCP_LOG_*)
        3. Consumer config dict (e.g. config.yaml `logging:` section)
        4. Built-in defaults
        """
        raw = config_dict or {}

        # Handle nested filenames dict e.g. {filenames: {app: "...", access: "...", error: "..."}}
        raw_filenames = raw.get("filenames") if isinstance(raw.get("filenames"), dict) else {}

        # Extract tier 3 (config dict)
        cfg_dir = raw.get("dir") or raw.get("log_dir")
        cfg_app = raw_filenames.get("app") or raw.get("app_filename") or raw.get("app_file")
        cfg_access = raw_filenames.get("access") or raw.get("access_filename") or raw.get("access_file")
        cfg_error = raw_filenames.get("error") or raw.get("error_filename") or raw.get("error_file")
        cfg_level = raw.get("level") or raw.get("log_level")
        cfg_max_bytes = raw.get("max_bytes")
        cfg_backup_count = raw.get("backup_count")
        cfg_enable_console = raw.get("enable_console")
        cfg_enable_trace = raw.get("enable_trace_injection")
        cfg_sensitive = raw.get("sensitive_keys")

        # Extract tier 2 (environment variables)
        env_dir = os.getenv("MCP_LOG_DIR")
        env_app = os.getenv("MCP_LOG_APP_FILE")
        env_access = os.getenv("MCP_LOG_ACCESS_FILE")
        env_error = os.getenv("MCP_LOG_ERROR_FILE")
        env_level = os.getenv("MCP_LOG_LEVEL")
        env_max_bytes = os.getenv("MCP_LOG_MAX_BYTES")
        env_backup_count = os.getenv("MCP_LOG_BACKUP_COUNT")
        env_console = os.getenv("MCP_LOG_ENABLE_CONSOLE") or os.getenv("MCP_LOG_CONSOLE")
        env_trace = os.getenv("MCP_LOG_ENABLE_TRACE_INJECTION") or os.getenv("MCP_LOG_TRACE_INJECTION")

        # Resolve tier 1 (overrides kwargs) with fallback to tier 2, tier 3, and default
        def pick(override_key: str, env_val: Any, cfg_val: Any, default_val: Any) -> Any:
            if override_key in overrides and overrides[override_key] is not None:
                return overrides[override_key]
            if env_val is not None and str(env_val).strip() != "":
                return env_val
            if cfg_val is not None:
                return cfg_val
            return default_val

        final_log_dir = str(pick("log_dir", env_dir, cfg_dir, ".runtime/logs"))
        final_access_filename = str(pick("access_filename", env_access, cfg_access, "access.log"))
        final_app_filename = pick("app_filename", env_app, cfg_app, None)
        if final_app_filename is not None:
            final_app_filename = str(final_app_filename)
        final_error_filename = str(pick("error_filename", env_error, cfg_error, "error.log"))
        final_level = str(pick("level", env_level, cfg_level, "INFO")).upper()
        final_max_bytes = _parse_int(pick("max_bytes", env_max_bytes, cfg_max_bytes, 10 * 1024 * 1024), 10 * 1024 * 1024)
        final_backup_count = _parse_int(pick("backup_count", env_backup_count, cfg_backup_count, 5), 5)
        final_enable_console = _parse_bool(pick("enable_console", env_console, cfg_enable_console, True), True)
        final_enable_trace = _parse_bool(pick("enable_trace_injection", env_trace, cfg_enable_trace, True), True)

        final_sensitive = overrides.get("sensitive_keys") or cfg_sensitive
        sensitive_list = list(final_sensitive) if isinstance(final_sensitive, (list, tuple)) else None

        inst = cls(
            log_dir=final_log_dir,
            access_filename=final_access_filename,
            app_filename=final_app_filename,
            error_filename=final_error_filename,
            level=final_level,
            max_bytes=final_max_bytes,
            backup_count=final_backup_count,
            enable_console=final_enable_console,
            enable_trace_injection=final_enable_trace,
        )
        if sensitive_list is not None:
            inst.sensitive_keys = sensitive_list
        return inst
