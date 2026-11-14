"""Central constants and single-source version definition for mcp-server-core."""
from __future__ import annotations

import importlib.metadata
from pathlib import Path

CORE_PACKAGE_NAME = "mcp-server-core"

try:
    __version__ = importlib.metadata.version(CORE_PACKAGE_NAME)
except Exception:
    __version__ = "0.6.0"

DEFAULT_MCP_PORT: int = 8788
DEFAULT_FALLBACK_PORTS: set[int] = {DEFAULT_MCP_PORT}
DEFAULT_TUNNEL_METRICS_PORT: int = 20245

DEFAULT_GLOBAL_MCP_DIR: Path = Path.home() / ".mcp"
DEFAULT_GLOBAL_ENV_FILE: Path = DEFAULT_GLOBAL_MCP_DIR / ".env"

DEFAULT_OAUTH_SCOPES: list[str] = [
    "openid",
    "profile",
    "email",
    "mcp:read",
    "mcp:write",
]

DEFAULT_CHATGPT_REDIRECT_URIS: list[str] = [
    "https://chatgpt.com/connector_platform_oauth_redirect",
]
