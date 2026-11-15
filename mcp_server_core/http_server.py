"""Generic MCP HTTP Server & ASGI Transport Layer.

Provides reusable ASGI application assembly, CORS setup, authentication middleware,
and standard RFC 9728/8414/7591 OAuth discovery routes for any FastMCP server.
"""
from __future__ import annotations

import os
import socket
import time
from typing import Any, Callable

from .console import configure_console_encoding

configure_console_encoding()

from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

try:
    from mcp.server.fastmcp import FastMCP
except (ImportError, ModuleNotFoundError):
    from mcp.server.mcpserver import MCPServer as FastMCP

from .env import DeploymentEnvConfig
from .logging.manager import get_access_logger
from .logging.trace import (
    extract_or_generate_trace_id,
    reset_current_trace_id,
    set_current_trace_id,
)
from .oauth import (
    LocalOAuthServer,
    get_server_public_url,
    oauth_authorization_server_metadata_endpoint,
    oauth_authorize_endpoint,
    oauth_jwks_endpoint,
    oauth_protected_resource_endpoint,
    oauth_register_endpoint,
    oauth_token_endpoint,
)


def get_local_ip() -> str:
    """Attempt to detect the primary local IPv4 address for network access."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


class TraceContextMiddleware:
    """Extract and propagate Cloudflare Ray ID / X-Request-ID across the async request lifecycle."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = scope.get("headers", [])
        trace_id = extract_or_generate_trace_id(headers)
        token = set_current_trace_id(trace_id)
        if "state" not in scope:
            scope["state"] = {}
        scope["state"]["trace_id"] = trace_id

        # Check if incoming request had cf-ray
        incoming_cf_ray = None
        for k, v in headers:
            if isinstance(k, bytes) and k.lower() == b"cf-ray":
                incoming_cf_ray = v
                break

        async def send_wrapper(message: Any) -> None:
            if message["type"] == "http.response.start":
                resp_headers = list(message.get("headers", []))
                resp_headers.append((b"x-trace-id", trace_id.encode("latin1")))
                if incoming_cf_ray:
                    resp_headers.append((b"cf-ray", incoming_cf_ray))
                message["headers"] = resp_headers
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            reset_current_trace_id(token)


class AccessLogMiddleware:
    """Asynchronous, non-blocking HTTP access log middleware."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start_time = time.perf_counter()
        status_code = 500

        client = scope.get("client")
        client_str = f"{client[0]}:{client[1]}" if client else "127.0.0.1"

        # Check for proxy / CF client IP
        for k, v in scope.get("headers", []):
            if isinstance(k, bytes) and k.lower() in (b"cf-connecting-ip", b"x-forwarded-for"):
                ip_val = v.decode("latin1", errors="ignore").split(",")[0].strip()
                if ip_val:
                    client_str = ip_val
                    break

        async def send_wrapper(message: Any) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message.get("status", 200)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            method = scope.get("method", "GET")
            path = scope.get("path", "/")
            http_version = scope.get("http_version", "1.1")
            access_logger = get_access_logger()
            access_logger.info(
                f'{client_str} - "{method} {path} HTTP/{http_version}" {status_code} {duration_ms:.2f}ms'
            )


class NoCacheMiddleware:
    """Enforce strict no-cache/no-store headers on all MCP, health, and discovery endpoints.

    Pure ASGI middleware that injects cache-busting headers without buffering streaming
    responses or interfering with HTTP/SSE connections.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Any) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((b"cache-control", b"no-cache, no-store, must-revalidate, max-age=0"))
                headers.append((b"pragma", b"no-cache"))
                headers.append((b"expires", b"0"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


class HTTPAuthenticationMiddleware:
    """Pure ASGI API Key / Bearer Token & OAuth 2.1 authentication middleware for HTTP MCP.

    Executes lightweight authentication checks without buffering responses or interfering with
    streaming SSE/HTTP connections.
    """

    def __init__(
        self,
        app: Any,
        oauth_server: LocalOAuthServer,
        require_auth: bool = False,
        allow_query_auth: bool = False,
        enable_public_oauth: bool = True,
    ) -> None:
        self.app = app
        self.oauth_server = oauth_server
        self.require_auth = require_auth
        self.allow_query_auth = allow_query_auth
        self.enable_public_oauth = enable_public_oauth

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)

        # 1. Allow CORS pre-flight
        if request.method == "OPTIONS":
            await self.app(scope, receive, send)
            return

        # 2. Public health check, OAuth and metadata endpoints require no auth
        path = request.url.path
        if (
            path in ("/", "/health", "/docs")
            or path.startswith(("/.well-known/", "/oauth/"))
            or path.endswith(
                (
                    "/.well-known/oauth-protected-resource",
                    "/.well-known/oauth-authorization-server",
                    "/.well-known/openid-configuration",
                )
            )
        ):
            await self.app(scope, receive, send)
            return

        # 3. If authentication is not enforced, proceed
        if not self.require_auth:
            await self.app(scope, receive, send)
            return

        # 4. Extract token from Authorization Header (or URL query only if explicitly allowed)
        token = ""
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        elif self.allow_query_auth:
            if "token" in request.query_params:
                token = request.query_params.get("token", "").strip()
            elif "key" in request.query_params:
                token = request.query_params.get("key", "").strip()

        eff_env = getattr(self.oauth_server, "config", None)
        eff_trust = getattr(self.oauth_server, "trust_proxy_headers", None)
        public_url = get_server_public_url(request, trust_override=eff_trust, env_cfg=eff_env)

        if not token:
            if self.enable_public_oauth:
                challenge = f'Bearer resource_metadata="{public_url}/.well-known/oauth-protected-resource"'
                msg = "Authentication required. Please authenticate via OAuth or provide Bearer token in Authorization header."
            else:
                challenge = 'Bearer error="invalid_token"'
                msg = "Direct public access to this backend is disabled. Please connect through your configured MCP portal or provide a valid Bearer token."
            resp = JSONResponse(
                {
                    "error": "unauthorized",
                    "message": msg,
                },
                status_code=401,
                headers={"WWW-Authenticate": challenge, "Access-Control-Allow-Origin": "*"},
            )
            await resp(scope, receive, send)
            return

        if not self.oauth_server.is_token_valid(token):
            if self.enable_public_oauth:
                challenge = f'Bearer error="invalid_token", resource_metadata="{public_url}/.well-known/oauth-protected-resource"'
            else:
                challenge = 'Bearer error="invalid_token"'
            resp = JSONResponse(
                {"error": "forbidden", "message": "Invalid API Key or OAuth Token."},
                status_code=403,
                headers={"WWW-Authenticate": challenge, "Access-Control-Allow-Origin": "*"},
            )
            await resp(scope, receive, send)
            return

        await self.app(scope, receive, send)


def mount_mcp_oauth_routes(
    server: FastMCP,
    oauth_server: LocalOAuthServer,
    service_name: str = "mcp_service",
    root_info_builder: Callable[[Request], dict[str, Any]] | None = None,
    enable_public_oauth: bool = True,
    service_title: str | None = None,
    custom_consent_renderer: Callable[..., str] | None = None,
    custom_scopes: list[str] | None = None,
    custom_issuer: str | None = None,
    allow_plain_pkce: bool | None = None,
) -> None:
    """Mount standard OAuth 2.1 metadata, authorization, token, and health routes on FastMCP."""
    resolved_title = service_title or service_name.replace("_", " ").title()

    # 1. Custom informative root endpoint
    @server.custom_route("/", methods=["GET", "OPTIONS"])
    async def root_info(request: Request) -> Response:
        if root_info_builder:
            payload = root_info_builder(request)
        else:
            payload = {
                "status": "online",
                "service": service_name,
                "endpoints": {
                    "health": "/health",
                    "oauth_protected_resource": "/.well-known/oauth-protected-resource",
                    "oauth_authorization_server": "/.well-known/oauth-authorization-server",
                    "oauth_register": "/oauth/register",
                    "oauth_authorize": "/oauth/authorize",
                    "oauth_token": "/oauth/token",
                },
            }
        return JSONResponse(payload, headers={"Access-Control-Allow-Origin": "*"})

    # 2. Health check endpoint
    @server.custom_route("/health", methods=["GET", "OPTIONS"])
    async def health_check(request: Request) -> Response:
        return JSONResponse(
            {"status": "healthy", "service": service_name},
            headers={"Access-Control-Allow-Origin": "*"},
        )

    # 3. RFC 9728 Protected Resource Metadata (ChatGPT 探测入口)
    @server.custom_route("/.well-known/oauth-protected-resource", methods=["GET", "OPTIONS"])
    @server.custom_route("/.well-known/oauth-protected-resource/mcp", methods=["GET", "OPTIONS"])
    @server.custom_route("/mcp/.well-known/oauth-protected-resource", methods=["GET", "OPTIONS"])
    async def protected_resource(request: Request) -> Response:
        if not enable_public_oauth:
            return JSONResponse(
                {
                    "error": "oauth_disabled",
                    "message": "Public OAuth registration is disabled on this backend.",
                },
                status_code=404,
                headers={"Access-Control-Allow-Origin": "*"},
            )
        return await oauth_protected_resource_endpoint(
            request,
            custom_scopes=custom_scopes,
            custom_issuer=custom_issuer,
            oauth_server=oauth_server,
            env_cfg=getattr(oauth_server, "config", None),
        )

    # 4. RFC 8414 Authorization Server Metadata (OAuth 2.1 发现入口)
    @server.custom_route("/.well-known/oauth-authorization-server", methods=["GET", "OPTIONS"])
    @server.custom_route("/.well-known/oauth-authorization-server/mcp", methods=["GET", "OPTIONS"])
    @server.custom_route("/mcp/.well-known/oauth-authorization-server", methods=["GET", "OPTIONS"])
    @server.custom_route("/.well-known/openid-configuration", methods=["GET", "OPTIONS"])
    @server.custom_route("/.well-known/openid-configuration/mcp", methods=["GET", "OPTIONS"])
    @server.custom_route("/mcp/.well-known/openid-configuration", methods=["GET", "OPTIONS"])
    async def authorization_server_metadata(request: Request) -> Response:
        if not enable_public_oauth:
            return JSONResponse(
                {"error": "oauth_disabled", "message": "Public OAuth discovery is disabled on this backend."},
                status_code=404,
                headers={"Access-Control-Allow-Origin": "*"},
            )
        effective_allow_plain = allow_plain_pkce if allow_plain_pkce is not None else getattr(oauth_server, "allow_plain_pkce", None)
        return await oauth_authorization_server_metadata_endpoint(
            request,
            custom_scopes=custom_scopes,
            custom_issuer=custom_issuer,
            allow_plain_pkce=effective_allow_plain,
            oauth_server=oauth_server,
            env_cfg=getattr(oauth_server, "config", None),
        )

    # 5. RFC 7591 Dynamic Client Registration
    @server.custom_route("/oauth/register", methods=["POST", "OPTIONS"])
    async def oauth_register(request: Request) -> Response:
        if not enable_public_oauth:
            return JSONResponse(
                {
                    "error": "registration_disabled",
                    "error_description": "Public OAuth registration on this endpoint is disabled.",
                },
                status_code=403,
                headers={"Access-Control-Allow-Origin": "*"},
            )
        return await oauth_register_endpoint(request, oauth_server)

    # 6. OAuth 2.1 Authorization Code Consent Page
    @server.custom_route("/oauth/authorize", methods=["GET", "POST", "OPTIONS"])
    async def oauth_authorize(request: Request) -> Response:
        if not enable_public_oauth:
            return JSONResponse(
                {"error": "authorization_disabled", "message": "OAuth consent is disabled on this backend."},
                status_code=403,
                headers={"Access-Control-Allow-Origin": "*"},
            )
        return await oauth_authorize_endpoint(
            request,
            oauth_server,
            service_title=resolved_title,
            consent_renderer=custom_consent_renderer,
        )

    # 7. OAuth 2.1 Token Exchange
    @server.custom_route("/oauth/token", methods=["POST", "OPTIONS"])
    async def oauth_token(request: Request) -> Response:
        if not enable_public_oauth:
            return JSONResponse(
                {"error": "token_endpoint_disabled", "message": "OAuth token exchange is disabled on this backend."},
                status_code=403,
                headers={"Access-Control-Allow-Origin": "*"},
            )
        return await oauth_token_endpoint(request, oauth_server)

    # 8. JWKS Public Keys Endpoint
    @server.custom_route("/oauth/jwks.json", methods=["GET", "OPTIONS"])
    @server.custom_route("/.well-known/jwks.json", methods=["GET", "OPTIONS"])
    async def oauth_jwks(request: Request) -> Response:
        return await oauth_jwks_endpoint(request)


def create_mcp_asgi_app(
    server: FastMCP,
    env_cfg: DeploymentEnvConfig,
    oauth_server: LocalOAuthServer,
    require_auth: bool | None = None,
) -> Starlette:
    """Build the final Starlette application with CORS and authentication middlewares."""
    is_auth_required = env_cfg.require_auth if require_auth is None else require_auth

    app = server.streamable_http_app()
    app.add_middleware(NoCacheMiddleware)
    app.add_middleware(
        HTTPAuthenticationMiddleware,
        oauth_server=oauth_server,
        require_auth=is_auth_required,
        allow_query_auth=env_cfg.allow_query_auth,
        enable_public_oauth=env_cfg.enable_public_oauth,
    )
    cors_origins = getattr(env_cfg, "cors_origins", None)
    if not cors_origins:
        cors_env = os.getenv("MCP_CORS_ORIGINS", "*").strip()
        cors_origins = [o.strip() for o in cors_env.split(",") if o.strip()] if cors_env != "*" else ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*", "WWW-Authenticate", "Mcp-Session-Id", "X-Trace-ID", "CF-Ray"],
    )
    app.add_middleware(AccessLogMiddleware)
    app.add_middleware(TraceContextMiddleware)
    return app
