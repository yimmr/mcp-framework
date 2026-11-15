"""FastMCP Tool Observability Aspect and Interception Engine."""
from __future__ import annotations

import contextvars
import functools
import inspect
import json
import logging
import time
from typing import Any, Callable

from .manager import get_log_manager
from .sanitizer import (
    PayloadHook,
    sanitize_arguments,
    summarize_tool_result,
)
from .trace import (
    generate_local_trace_id,
    generate_trace_id,
    get_current_trace_id,
    reset_current_trace_id,
    set_current_trace_id,
)

_IN_OBSERVED_TOOL: contextvars.ContextVar[bool] = contextvars.ContextVar("_IN_OBSERVED_TOOL", default=False)
_GLOBAL_PAYLOAD_HOOK: PayloadHook | None = None


def set_global_payload_hook(hook: PayloadHook | None) -> None:
    """Register a global payload sanitization/summary hook."""
    global _GLOBAL_PAYLOAD_HOOK
    _GLOBAL_PAYLOAD_HOOK = hook


def get_global_payload_hook() -> PayloadHook | None:
    """Get the current global payload hook."""
    return _GLOBAL_PAYLOAD_HOOK


def _get_app_and_error_loggers() -> tuple[logging.Logger, logging.Logger]:
    mgr = get_log_manager()
    if mgr:
        return mgr.get_app_logger(), mgr.get_error_logger()
    return logging.getLogger("mcp.app"), logging.getLogger("mcp.error")


def observe_tool(
    name: str | None = None,
    payload_hook: PayloadHook | None = None,
) -> Callable:
    """Decorator to instrument any standalone sync or async tool function with observability.

    - High-precision timing (time.perf_counter)
    - Input sanitization (key masking, secret redaction, payload summaries)
    - Success summary logging to App Stream
    - Complete exception traceback logging to Error Stream
    - Trace ID propagation
    """

    def decorator(fn: Any) -> Any:
        tool_name = name or getattr(fn, "__name__", "unnamed_tool")

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                if _IN_OBSERVED_TOOL.get():
                    return await fn(*args, **kwargs)

                token_tool = _IN_OBSERVED_TOOL.set(True)
                tid = get_current_trace_id()
                token_trace = None
                if not tid:
                    tid = generate_local_trace_id()
                    token_trace = set_current_trace_id(tid)

                app_logger, error_logger = _get_app_and_error_loggers()
                effective_hook = payload_hook or _GLOBAL_PAYLOAD_HOOK
                mgr = get_log_manager()
                sens_keys = mgr.config.sensitive_keys if (mgr and mgr.config) else None
                sanitized_args = sanitize_arguments(tool_name, kwargs, payload_hook=effective_hook, sensitive_keys=sens_keys)
                args_preview = json.dumps(sanitized_args, ensure_ascii=False) if sanitized_args else "{}"

                app_logger.info(f"Tool started: {tool_name} | args: {args_preview}")
                t0 = time.perf_counter()
                try:
                    result = await fn(*args, **kwargs)
                    duration_ms = (time.perf_counter() - t0) * 1000.0
                    summary = summarize_tool_result(result)
                    app_logger.info(f"Tool finished: {tool_name} | duration: {duration_ms:.2f}ms | result: {summary}")
                    return result
                except Exception as exc:
                    duration_ms = (time.perf_counter() - t0) * 1000.0
                    error_logger.exception(
                        f"Tool failed: {tool_name} | duration: {duration_ms:.2f}ms | error: {type(exc).__name__}: {exc}"
                    )
                    _annotate_exception_with_trace(exc, tid)
                    raise
                finally:
                    _IN_OBSERVED_TOOL.reset(token_tool)
                    if token_trace is not None:
                        reset_current_trace_id(token_trace)

            return async_wrapper

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            if _IN_OBSERVED_TOOL.get():
                return fn(*args, **kwargs)

            token_tool = _IN_OBSERVED_TOOL.set(True)
            tid = get_current_trace_id()
            token_trace = None
            if not tid:
                tid = generate_local_trace_id()
                token_trace = set_current_trace_id(tid)

            app_logger, error_logger = _get_app_and_error_loggers()
            effective_hook = payload_hook or _GLOBAL_PAYLOAD_HOOK
            mgr = get_log_manager()
            sens_keys = mgr.config.sensitive_keys if (mgr and mgr.config) else None
            sanitized_args = sanitize_arguments(tool_name, kwargs, payload_hook=effective_hook, sensitive_keys=sens_keys)
            args_preview = json.dumps(sanitized_args, ensure_ascii=False) if sanitized_args else "{}"

            app_logger.info(f"Tool started: {tool_name} | args: {args_preview}")
            t0 = time.perf_counter()
            try:
                result = fn(*args, **kwargs)
                duration_ms = (time.perf_counter() - t0) * 1000.0
                summary = summarize_tool_result(result)
                app_logger.info(f"Tool finished: {tool_name} | duration: {duration_ms:.2f}ms | result: {summary}")
                return result
            except Exception as exc:
                duration_ms = (time.perf_counter() - t0) * 1000.0
                error_logger.exception(
                    f"Tool failed: {tool_name} | duration: {duration_ms:.2f}ms | error: {type(exc).__name__}: {exc}"
                )
                _annotate_exception_with_trace(exc, tid)
                raise
            finally:
                _IN_OBSERVED_TOOL.reset(token_tool)
                if token_trace is not None:
                    reset_current_trace_id(token_trace)

        return sync_wrapper

    if callable(name):
        actual_fn = name
        name = None
        return decorator(actual_fn)
    return decorator


def _annotate_exception_with_trace(exc: Exception, trace_id: str) -> None:
    """Ensure the exception string or message contains the trace identifier."""
    if not hasattr(exc, "_mcp_trace_id"):
        setattr(exc, "_mcp_trace_id", trace_id)


def instrument_fastmcp_server(
    server: Any,
    payload_hook: PayloadHook | None = None,
) -> None:
    """Seamlessly instrument a FastMCP server instance so all registered tools are observed.

    Intercepts FastMCP at the ToolManager layer so tools executed via real MCP transports
    (Streamable HTTP, stdio, SSE) as well as direct server.call_tool() invocations are
    consistently and automatically observed with high-precision timing, argument sanitization,
    trace propagation, and ToolError error formatting.
    """
    if getattr(server, "_mcp_observability_instrumented", False):
        return
    server._mcp_observability_instrumented = True

    tool_mgr = getattr(server, "_tool_manager", None)
    if tool_mgr is not None and hasattr(tool_mgr, "call_tool") and callable(tool_mgr.call_tool):
        orig_tm_call_tool = tool_mgr.call_tool

        @functools.wraps(orig_tm_call_tool)
        async def instrumented_tm_call_tool(
            name: str,
            arguments: dict[str, Any],
            context: Any = None,
            convert_result: bool = False,
        ) -> Any:
            if _IN_OBSERVED_TOOL.get():
                return await orig_tm_call_tool(name, arguments, context=context, convert_result=convert_result)

            token_tool = _IN_OBSERVED_TOOL.set(True)

            # Resolve trace ID: request context > context object > registry > local fallback
            tid = get_current_trace_id()
            if not tid and context:
                try:
                    req_ctx = getattr(context, "_request_context", None) or getattr(context, "request_context", None)
                    req = getattr(req_ctx, "request", None) if req_ctx else None
                    if req is not None:
                        if hasattr(req, "scope") and isinstance(req.scope, dict):
                            tid = req.scope.get("state", {}).get("trace_id")
                            if not tid and req.scope.get("headers"):
                                from .trace import extract_or_generate_trace_id
                                tid = extract_or_generate_trace_id(req.scope.get("headers"))
                        elif hasattr(req, "headers"):
                            from .trace import extract_or_generate_trace_id
                            tid = extract_or_generate_trace_id(req.headers)
                except Exception:
                    pass

            if not tid:
                tid = generate_local_trace_id()

            token_trace = set_current_trace_id(tid)

            app_logger, error_logger = _get_app_and_error_loggers()
            effective_hook = payload_hook or _GLOBAL_PAYLOAD_HOOK

            mgr = get_log_manager()
            sens_keys = mgr.config.sensitive_keys if (mgr and mgr.config) else None

            sanitized_args = sanitize_arguments(name, arguments, payload_hook=effective_hook, sensitive_keys=sens_keys)
            try:
                args_str = json.dumps(sanitized_args, ensure_ascii=False)
            except Exception:
                args_str = str(sanitized_args)

            app_logger.info(f"Tool execution started: {name} | arguments: {args_str}")
            t0 = time.perf_counter()
            try:
                result = await orig_tm_call_tool(name, arguments, context=context, convert_result=convert_result)
                duration_ms = (time.perf_counter() - t0) * 1000.0
                summary = summarize_tool_result(result)
                app_logger.info(f"Tool execution completed: {name} | duration: {duration_ms:.2f}ms | result: {summary}")
                return result
            except Exception as exc:
                duration_ms = (time.perf_counter() - t0) * 1000.0
                error_logger.exception(
                    f"Tool execution failed: {name} | duration: {duration_ms:.2f}ms | error: {type(exc).__name__}: {exc}"
                )
                _annotate_exception_with_trace(exc, tid)

                # Ensure client-visible message contains [trace_id: {tid}]
                err_msg = str(exc)
                if f"trace_id: {tid}" not in err_msg and not err_msg.startswith(f"[{tid}]"):
                    new_msg = f"[trace_id: {tid}] {err_msg}"
                else:
                    new_msg = err_msg

                try:
                    from mcp.server.fastmcp.exceptions import ToolError
                    raise ToolError(new_msg) from exc
                except ImportError:
                    pass
                raise
            finally:
                _IN_OBSERVED_TOOL.reset(token_tool)
                if token_trace is not None:
                    reset_current_trace_id(token_trace)

        tool_mgr.call_tool = instrumented_tm_call_tool

    orig_call_tool = getattr(server, "call_tool", None)
    if orig_call_tool is not None and callable(orig_call_tool):
        @functools.wraps(orig_call_tool)
        async def instrumented_call_tool(name: str, arguments: dict[str, Any]) -> Any:
            if _IN_OBSERVED_TOOL.get():
                return await orig_call_tool(name, arguments)
            # If tool_manager was intercepted, orig_call_tool delegates to tool_manager.call_tool
            if tool_mgr is not None and hasattr(tool_mgr, "call_tool"):
                return await orig_call_tool(name, arguments)

            # Fallback for servers without _tool_manager
            token_tool = _IN_OBSERVED_TOOL.set(True)
            tid = get_current_trace_id() or generate_local_trace_id()
            token_trace = set_current_trace_id(tid)
            app_logger, error_logger = _get_app_and_error_loggers()
            effective_hook = payload_hook or _GLOBAL_PAYLOAD_HOOK
            mgr = get_log_manager()
            sens_keys = mgr.config.sensitive_keys if (mgr and mgr.config) else None
            sanitized_args = sanitize_arguments(name, arguments, payload_hook=effective_hook, sensitive_keys=sens_keys)
            try:
                args_str = json.dumps(sanitized_args, ensure_ascii=False)
            except Exception:
                args_str = str(sanitized_args)

            app_logger.info(f"Tool execution started: {name} | arguments: {args_str}")
            t0 = time.perf_counter()
            try:
                result = await orig_call_tool(name, arguments)
                duration_ms = (time.perf_counter() - t0) * 1000.0
                summary = summarize_tool_result(result)
                app_logger.info(f"Tool execution completed: {name} | duration: {duration_ms:.2f}ms | result: {summary}")
                return result
            except Exception as exc:
                duration_ms = (time.perf_counter() - t0) * 1000.0
                error_logger.exception(
                    f"Tool execution failed: {name} | duration: {duration_ms:.2f}ms | error: {type(exc).__name__}: {exc}"
                )
                _annotate_exception_with_trace(exc, tid)

                err_msg = str(exc)
                if f"trace_id: {tid}" not in err_msg and not err_msg.startswith(f"[{tid}]"):
                    new_msg = f"[trace_id: {tid}] {err_msg}"
                else:
                    new_msg = err_msg

                try:
                    from mcp.server.fastmcp.exceptions import ToolError
                    raise ToolError(new_msg) from exc
                except ImportError:
                    pass
                raise
            finally:
                _IN_OBSERVED_TOOL.reset(token_tool)
                if token_trace is not None:
                    reset_current_trace_id(token_trace)

        server.call_tool = instrumented_call_tool
