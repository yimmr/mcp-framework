"""Unified Multi-Stream Rotating Log Manager."""
from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from .config import LoggingConfig
from .trace import TraceLogFilter

_GLOBAL_LOG_MANAGER: LogManager | None = None


class LogManager:
    """Manages the 3-stream decoupled rotating log engine:

    1. Access Stream (access.log): HTTP network traffic, response codes, latency, CF-Ray
    2. App Stream ({service_name}.log or app.log): Tool invocations, sanitized parameters, durations
    3. Error Stream (error.log): Warnings, errors, and complete exception stack traces

    All streams strictly converge in the project directory (<project_root>/.runtime/logs/)
    by default or in a consumer-configured directory, preventing OS global pollution.
    """

    def __init__(
        self,
        base_dir: Path | None = None,
        config: LoggingConfig | None = None,
        service_name: str | None = None,
    ) -> None:
        self.base_dir = (base_dir or Path.cwd()).resolve()
        self.config = config or LoggingConfig()
        self.service_name = service_name or "mcp_service"

        # Resolve log paths
        self.log_dir = self.config.resolve_log_dir(self.base_dir)
        self.access_file = self.log_dir / self.config.access_filename
        self.app_file = self.log_dir / self.config.resolve_app_filename(self.service_name)
        self.error_file = self.log_dir / self.config.error_filename

        self._trace_filter = TraceLogFilter()
        self._handlers: list[logging.Handler] = []

        self._setup_loggers()

    def _setup_loggers(self) -> None:
        numeric_level = getattr(logging, self.config.level.upper(), logging.INFO)

        # Standard log formatters
        app_fmt = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [trace_id: %(trace_id)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        access_fmt = logging.Formatter(
            fmt="%(asctime)s [trace_id: %(trace_id)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # 1. Access Stream Handler
        access_h = RotatingFileHandler(
            self.access_file,
            maxBytes=self.config.max_bytes,
            backupCount=self.config.backup_count,
            encoding="utf-8",
        )
        access_h.setLevel(logging.INFO)
        access_h.setFormatter(access_fmt)
        access_h.addFilter(self._trace_filter)
        self._handlers.append(access_h)

        access_logger = logging.getLogger("mcp.access")
        access_logger.setLevel(logging.INFO)
        access_logger.handlers.clear()
        access_logger.addHandler(access_h)
        access_logger.propagate = False

        # 2. App Stream Handler
        app_h = RotatingFileHandler(
            self.app_file,
            maxBytes=self.config.max_bytes,
            backupCount=self.config.backup_count,
            encoding="utf-8",
        )
        app_h.setLevel(numeric_level)
        app_h.setFormatter(app_fmt)
        app_h.addFilter(self._trace_filter)
        self._handlers.append(app_h)

        # 3. Error Stream Handler (WARNING, ERROR, CRITICAL + Tracebacks)
        error_h = RotatingFileHandler(
            self.error_file,
            maxBytes=self.config.max_bytes,
            backupCount=self.config.backup_count,
            encoding="utf-8",
        )
        error_h.setLevel(logging.WARNING)
        error_h.setFormatter(app_fmt)
        error_h.addFilter(self._trace_filter)
        self._handlers.append(error_h)

        # 4. Console Handler (optional mirror)
        console_h: logging.Handler | None = None
        if self.config.enable_console:
            console_h = logging.StreamHandler(sys.stdout)
            console_h.setLevel(numeric_level)
            console_h.setFormatter(app_fmt)
            console_h.addFilter(self._trace_filter)
            self._handlers.append(console_h)

        # Configure App Logger ("mcp.app" and root "mcp")
        app_logger = logging.getLogger("mcp.app")
        app_logger.setLevel(numeric_level)
        app_logger.handlers.clear()
        app_logger.addHandler(app_h)
        app_logger.addHandler(error_h)
        if console_h:
            app_logger.addHandler(console_h)
        app_logger.propagate = False

        # Configure dedicated Error Logger ("mcp.error")
        error_logger = logging.getLogger("mcp.error")
        error_logger.setLevel(logging.WARNING)
        error_logger.handlers.clear()
        error_logger.addHandler(error_h)
        error_logger.addHandler(app_h)
        if console_h:
            error_logger.addHandler(console_h)
        error_logger.propagate = False

    def get_logger(self, name: str | None = None) -> logging.Logger:
        """Get an application logger under the mcp namespace."""
        if not name:
            return logging.getLogger("mcp.app")
        if name.startswith("mcp."):
            return logging.getLogger(name)
        return logging.getLogger(f"mcp.{name}")

    def get_access_logger(self) -> logging.Logger:
        """Get the dedicated HTTP access stream logger."""
        return logging.getLogger("mcp.access")

    def get_app_logger(self) -> logging.Logger:
        """Get the primary tool execution stream logger."""
        return logging.getLogger("mcp.app")

    def get_error_logger(self) -> logging.Logger:
        """Get the error & exception stream logger."""
        return logging.getLogger("mcp.error")

    def close(self) -> None:
        """Flush and close all handlers (essential for Windows file lock release)."""
        for h in self._handlers:
            try:
                h.flush()
                h.close()
            except Exception:
                pass
        self._handlers.clear()

        for name in ("mcp.access", "mcp.app", "mcp.error"):
            lg = logging.getLogger(name)
            lg.handlers.clear()


def setup_logging(
    base_dir: Path | None = None,
    config: LoggingConfig | None = None,
    service_name: str | None = None,
    **kwargs: Any,
) -> LogManager:
    """Initialize or update the global LogManager instance."""
    global _GLOBAL_LOG_MANAGER

    if _GLOBAL_LOG_MANAGER is not None:
        _GLOBAL_LOG_MANAGER.close()

    resolved_config = config or LoggingConfig.from_dict_and_env(base_dir=base_dir, **kwargs)
    manager = LogManager(base_dir=base_dir, config=resolved_config, service_name=service_name)
    _GLOBAL_LOG_MANAGER = manager
    return manager


def get_log_manager() -> LogManager | None:
    """Retrieve the active global LogManager instance."""
    return _GLOBAL_LOG_MANAGER


def get_logger(name: str | None = None) -> logging.Logger:
    """Get an application logger under the mcp namespace."""
    if _GLOBAL_LOG_MANAGER:
        return _GLOBAL_LOG_MANAGER.get_logger(name)
    if not name:
        return logging.getLogger("mcp.app")
    if name.startswith("mcp."):
        return logging.getLogger(name)
    return logging.getLogger(f"mcp.{name}")


def get_access_logger() -> logging.Logger:
    """Get the active access stream logger."""
    if _GLOBAL_LOG_MANAGER:
        return _GLOBAL_LOG_MANAGER.get_access_logger()
    return logging.getLogger("mcp.access")


def get_app_logger() -> logging.Logger:
    """Get the active app stream logger."""
    if _GLOBAL_LOG_MANAGER:
        return _GLOBAL_LOG_MANAGER.get_app_logger()
    return logging.getLogger("mcp.app")


def get_error_logger() -> logging.Logger:
    """Get the active error stream logger."""
    if _GLOBAL_LOG_MANAGER:
        return _GLOBAL_LOG_MANAGER.get_error_logger()
    return logging.getLogger("mcp.error")

