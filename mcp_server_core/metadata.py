"""Service Metadata Model for MCP Server Core.

Provides unified service identification, branding, and protocol metadata across
ASGI endpoints, OAuth discovery, logging, and Cloudflare tunnel heartbeats.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .constants import DEFAULT_MCP_PORT, DEFAULT_OAUTH_SCOPES, __version__


@dataclass
class ServiceMetadata:
    """Unified service identity and protocol metadata carrier."""

    service_name: str = "mcp_service"
    service_title: str | None = None
    local_port: int = DEFAULT_MCP_PORT
    supported_scopes: list[str] = field(
        default_factory=lambda: list(DEFAULT_OAUTH_SCOPES)
    )
    user_agent: str = ""

    def __post_init__(self) -> None:
        if not self.service_title:
            self.service_title = (
                self.service_name.replace("_", " ").title()
                if self.service_name
                else "MCP Service"
            )

    def get_user_agent(self, version: str = "1.0", core_version: str | None = None) -> str:
        """Construct standard White-label User-Agent header string."""
        if self.user_agent:
            return self.user_agent
        name = self.service_name or "mcp-server"
        resolved_core_ver = core_version or __version__
        return f"{name}/{version} (mcp-server-core/{resolved_core_ver})"

    def to_dict(self) -> dict[str, Any]:
        """Convert metadata to dictionary representation."""
        return {
            "service_name": self.service_name,
            "service_title": self.service_title,
            "local_port": self.local_port,
            "supported_scopes": list(self.supported_scopes),
            "user_agent": self.get_user_agent(),
        }
