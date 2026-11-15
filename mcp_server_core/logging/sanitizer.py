"""Universal security sanitization and payload summary engine."""
from __future__ import annotations

import re
from typing import Any, Callable

# Regex patterns for string value redaction
_BEARER_PATTERN = re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]+", re.IGNORECASE)
_SEC_PREFIX_PATTERN = re.compile(r"sec_[A-Za-z0-9_\-]+", re.IGNORECASE)
_PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----")

DEFAULT_SENSITIVE_KEY_SUBSTRINGS = (
    "token",
    "key",
    "password",
    "secret",
    "auth",
    "credential",
    "api_key",
    "access_token",
    "private_key",
)

PayloadHook = Callable[[str, dict[str, Any]], dict[str, Any] | None]


SAFE_NON_SENSITIVE_KEYS = {
    "authorized_paths",
    "authorized_keys_file",
    "author",
    "authors",
    "authorization_url",
}


def is_sensitive_key(key: str, sensitive_keys: list[str] | None = None) -> bool:
    """Check if a dictionary key matches common sensitive information patterns.

    Uses token/boundary-aware matching to avoid false positives (e.g. 'authorized_paths').
    """
    k_lower = key.lower()
    if k_lower in SAFE_NON_SENSITIVE_KEYS:
        return False

    targets = sensitive_keys or DEFAULT_SENSITIVE_KEY_SUBSTRINGS
    tokens = set(re.split(r"[_\-.\s:]+", k_lower))

    for target in targets:
        t_lower = target.lower().strip()
        if not t_lower:
            continue
        if k_lower == t_lower:
            return True
        if "_" not in t_lower and "-" not in t_lower:
            if t_lower in tokens:
                return True
            if (
                k_lower.startswith(f"{t_lower}_")
                or k_lower.endswith(f"_{t_lower}")
                or f"_{t_lower}_" in k_lower
            ):
                return True
        else:
            if t_lower in k_lower:
                return True

    return False


def sanitize_string_value(val: str, max_str_len: int = 10_000) -> str:
    """Sanitize secrets inside string values and truncate massive payloads."""
    if not val:
        return val

    # Mask known token formats
    cleaned = _BEARER_PATTERN.sub(r"\1***", val)
    cleaned = _SEC_PREFIX_PATTERN.sub("sec_***", cleaned)
    cleaned = _PRIVATE_KEY_PATTERN.sub("[PRIVATE KEY MASKED]", cleaned)

    if len(cleaned) > max_str_len:
        preview = cleaned[:200].replace("\n", " ").replace("\r", "")
        return f"[truncated content: {len(cleaned)} chars, preview='{preview}...']"
    return cleaned


def sanitize_value(
    val: Any,
    sensitive_keys: list[str] | None = None,
    depth: int = 0,
    max_depth: int = 8,
) -> Any:
    """Recursively sanitize data structures (dicts, lists, tuples, primitives)."""
    if depth > max_depth:
        return "<max_depth_exceeded>"

    if isinstance(val, dict):
        sanitized: dict[str, Any] = {}
        for k, v in val.items():
            k_str = str(k)
            if is_sensitive_key(k_str, sensitive_keys):
                sanitized[k_str] = "***"
            else:
                sanitized[k_str] = sanitize_value(v, sensitive_keys=sensitive_keys, depth=depth + 1, max_depth=max_depth)
        return sanitized

    if isinstance(val, (list, tuple)):
        items = [sanitize_value(elem, sensitive_keys=sensitive_keys, depth=depth + 1, max_depth=max_depth) for elem in val]
        return type(val)(items)

    if isinstance(val, str):
        return sanitize_string_value(val)

    if isinstance(val, (bytes, bytearray)):
        return f"<bytes: {len(val)} bytes>"

    return val


def sanitize_arguments(
    tool_name: str,
    arguments: dict[str, Any],
    payload_hook: PayloadHook | None = None,
    sensitive_keys: list[str] | None = None,
) -> dict[str, Any]:
    """Sanitize tool input arguments applying optional consumer payload hook first."""
    args = dict(arguments or {})

    # Apply consumer-specific payload summary hook if provided
    if payload_hook is not None:
        try:
            hook_res = payload_hook(tool_name, args)
            if isinstance(hook_res, dict):
                args = hook_res
        except Exception:
            pass

    return sanitize_value(args, sensitive_keys=sensitive_keys)


def summarize_tool_result(result: Any, max_len: int = 300) -> str:
    """Produce a concise, human-readable summary of a tool execution result for logs."""
    if result is None:
        return "None"

    if isinstance(result, str):
        s = result.replace("\n", " ").replace("\r", " ").strip()
        if len(s) > max_len:
            return f"[str len={len(result)}: {s[:max_len]}...]"
        return f"[str: {s}]"

    if isinstance(result, dict):
        status = result.get("status")
        keys = list(result.keys())[:6]
        keys_summary = ", ".join(str(k) for k in keys)
        if len(result) > 6:
            keys_summary += f", ... (+{len(result) - 6} keys)"
        if status:
            return f"[dict: status={status}, keys=[{keys_summary}]]"
        return f"[dict: len={len(result)}, keys=[{keys_summary}]]"

    if isinstance(result, (list, tuple)):
        return f"[{type(result).__name__}: count={len(result)}]"

    # FastMCP ContentBlock or other objects
    res_str = str(result).replace("\n", " ").replace("\r", " ")
    if len(res_str) > max_len:
        return f"[{type(result).__name__}: {res_str[:max_len]}...]"
    return f"[{type(result).__name__}: {res_str}]"
