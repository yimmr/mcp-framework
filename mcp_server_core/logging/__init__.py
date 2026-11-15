"""Reusable Observability, Tracing and Multi-Stream Logging Engine for MCP."""
from __future__ import annotations

from .config import LoggingConfig
from .trace import (
    TraceLogFilter,
    extract_or_generate_trace_id,
    generate_trace_id,
    get_current_trace_id,
    reset_current_trace_id,
    set_current_trace_id,
)
from .sanitizer import (
    PayloadHook,
    is_sensitive_key,
    sanitize_arguments,
    sanitize_string_value,
    sanitize_value,
    summarize_tool_result,
)
from .manager import (
    LogManager,
    get_access_logger,
    get_app_logger,
    get_error_logger,
    get_log_manager,
    get_logger,
    setup_logging,
)
from .aspect import (
    get_global_payload_hook,
    instrument_fastmcp_server,
    observe_tool,
    set_global_payload_hook,
)

__all__ = [
    "LoggingConfig",
    "TraceLogFilter",
    "extract_or_generate_trace_id",
    "generate_trace_id",
    "get_current_trace_id",
    "set_current_trace_id",
    "reset_current_trace_id",
    "PayloadHook",
    "is_sensitive_key",
    "sanitize_arguments",
    "sanitize_string_value",
    "sanitize_value",
    "summarize_tool_result",
    "LogManager",
    "setup_logging",
    "get_log_manager",
    "get_logger",
    "get_access_logger",
    "get_app_logger",
    "get_error_logger",
    "observe_tool",
    "instrument_fastmcp_server",
    "set_global_payload_hook",
    "get_global_payload_hook",
]
