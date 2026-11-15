"""Distributed trace context management and log injection."""
from __future__ import annotations

import contextvars
import logging
import secrets
from typing import Any, Mapping

_CURRENT_TRACE_ID: contextvars.ContextVar[str] = contextvars.ContextVar("_CURRENT_TRACE_ID", default="")


def get_current_trace_id() -> str:
    """Retrieve the current execution trace ID, or empty string if unset."""
    return _CURRENT_TRACE_ID.get()


def set_current_trace_id(trace_id: str) -> contextvars.Token:
    """Bind a trace ID to the current asynchronous execution context."""
    return _CURRENT_TRACE_ID.set(trace_id)


def reset_current_trace_id(token: contextvars.Token) -> None:
    """Reset the trace ID contextvar to its previous state."""
    try:
        _CURRENT_TRACE_ID.reset(token)
    except Exception:
        pass


def generate_trace_id() -> str:
    """Generate a pseudo-random trace identifier (e.g. trace_8e1a2b3c)."""
    return f"trace_{secrets.token_hex(4)}"


def extract_or_generate_trace_id(headers: Any) -> str:
    """Extract trace ID from headers with priority:

    1. cf-ray (Cloudflare Gateway Ray ID)
    2. x-request-id (Standard proxy/client request ID)
    3. Auto-generated random trace ID
    """
    if headers is None:
        return generate_trace_id()

    # Case 1: ASGI scope headers format: list of (bytes, bytes)
    if isinstance(headers, (list, tuple)):
        cf_ray = None
        req_id = None
        for item in headers:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                k, v = item[0], item[1]
                k_str = k.decode("latin1", errors="ignore").lower() if isinstance(k, bytes) else str(k).lower()
                v_str = v.decode("latin1", errors="ignore").strip() if isinstance(v, bytes) else str(v).strip()
                if k_str == "cf-ray" and v_str:
                    cf_ray = v_str
                elif k_str == "x-request-id" and v_str:
                    req_id = v_str
        if cf_ray:
            return cf_ray
        if req_id:
            return req_id
        return generate_trace_id()

    # Case 2: Mapping / dict / Starlette Headers
    if hasattr(headers, "get"):
        cf_ray = headers.get("cf-ray") or headers.get("CF-Ray") or headers.get("Cf-Ray")
        if cf_ray and str(cf_ray).strip():
            return str(cf_ray).strip()

        req_id = headers.get("x-request-id") or headers.get("X-Request-ID") or headers.get("X-Request-Id")
        if req_id and str(req_id).strip():
            return str(req_id).strip()

    return generate_trace_id()


class TraceLogFilter(logging.Filter):
    """Logging filter that injects the current `trace_id` into every LogRecord."""

    def filter(self, record: logging.LogRecord) -> bool:
        tid = get_current_trace_id()
        record.trace_id = tid if tid else "-"
        return True
