"""Distributed trace context management and log injection."""
from __future__ import annotations

import contextvars
import logging
import secrets
from typing import Any, Mapping

_CURRENT_TRACE_ID: contextvars.ContextVar[str] = contextvars.ContextVar("_CURRENT_TRACE_ID", default="")
_REQUEST_TRACE_REGISTRY: dict[tuple[str, str], str] = {}


def bind_request_trace(session_id: str, request_id: str, trace_id: str) -> None:
    """Bind a trace ID to a specific MCP (session_id, request_id) pair."""
    if session_id and request_id:
        _REQUEST_TRACE_REGISTRY[(str(session_id), str(request_id))] = trace_id


def unbind_request_trace(session_id: str, request_id: str) -> None:
    """Remove a previously bound (session_id, request_id) trace ID."""
    _REQUEST_TRACE_REGISTRY.pop((str(session_id), str(request_id)), None)


def get_request_trace(session_id: str, request_id: str) -> str | None:
    """Look up trace ID for a (session_id, request_id) pair."""
    return _REQUEST_TRACE_REGISTRY.get((str(session_id), str(request_id)))


def get_current_trace_id() -> str:
    """Retrieve the current execution trace ID, or empty string if unset.

    Resolution order:
    1. Active MCP lowlevel RequestContext (binds the specific HTTP request e.g. cf-ray)
    2. Request trace registry via (session_id, request_id)
    3. Explicit contextvar `_CURRENT_TRACE_ID`
    """
    try:
        from mcp.server.lowlevel.server import request_ctx
        req_ctx = request_ctx.get()
        if req_ctx:
            req = getattr(req_ctx, "request", None)
            if req is not None:
                if hasattr(req, "scope") and isinstance(req.scope, dict):
                    tid = req.scope.get("state", {}).get("trace_id")
                    if tid:
                        return str(tid)
                    headers = req.scope.get("headers")
                    if headers:
                        return extract_or_generate_trace_id(headers)
                elif hasattr(req, "headers"):
                    return extract_or_generate_trace_id(req.headers)

            session = getattr(req_ctx, "session", None)
            sess_id = getattr(session, "session_id", None) if session else None
            req_id = getattr(req_ctx, "request_id", None)
            if sess_id and req_id:
                reg_tid = get_request_trace(str(sess_id), str(req_id))
                if reg_tid:
                    return reg_tid
    except Exception:
        pass

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


def generate_local_trace_id() -> str:
    """Generate a fallback local trace identifier for un-traced local calls."""
    return f"trace_local_{secrets.token_hex(4)}"


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
