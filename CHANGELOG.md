# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-11-15

### Added
- **Global Configuration (`~/.mcp/.env`)**: Added user-level centralized configuration support (`~/.mcp/.env`) for shared infrastructure settings (such as `CLOUDFLARE_TUNNEL_TOKEN`, `CLOUDFLARED_PATH`, and metrics ports) with cascading fallback across `DeploymentEnvConfig.load()`, `get_tunnel_token()`, `find_cloudflared()`, and `mcp-server-core status`.
- **Constants Centralization**: Created `mcp_server_core.constants` containing `DEFAULT_MCP_PORT`, `DEFAULT_FALLBACK_PORTS`, `DEFAULT_TUNNEL_METRICS_PORT`, `DEFAULT_OAUTH_SCOPES`, and `__version__`.
- **Console Encoding**: Added `mcp_server_core.console.configure_console_encoding` for idempotent, cross-platform UTF-8 terminal configuration.
- **Typing Marker**: Added PEP 561 `py.typed` marker file.
- **Atomic Environment Updates**: Added atomic temporary-file-and-replace mechanism for `.env` updates in `update_env_variable`.
- **Explicit API Key Generation**: Added `ensure_api_key()` to decouple secret creation from configuration reading.
- **Process Verification**: Added `is_mcp_or_related_process()` guard before terminating PIDs to prevent killing unrelated system processes.
- **POSIX Port Fallback**: Added `ss -tlpn` fallback in `find_pid_by_port()` when `lsof` is not installed on Linux environments.
- **Configurable CORS**: Added `MCP_CORS_ORIGINS` environment variable support to customize Starlette CORS origins.

### Changed
- **Safe Configuration Loading & Override Precedence**: `DeploymentEnvConfig.load()` is now a pure configuration loader without global `os.environ` mutation, completely preventing cross-project environment leakage in multi-project environments, with strict precedence (overrides -> .env -> os.environ -> defaults).
- **Pure ASGI Middleware Architecture**: Converted both `NoCacheMiddleware` and `HTTPAuthenticationMiddleware` from `BaseHTTPMiddleware` to pure ASGI middleware, completely eliminating `BaseHTTPMiddleware` overhead and ensuring unbuffered incremental SSE streaming responses.
- **Runtime Directory & Reverse Proxy Propagation**: Full end-to-end propagation of `MCP_RUNTIME_DIR` across server PID tracking, process termination, and system tray supervisor; wired `MCP_TRUST_PROXY_HEADERS` and `DeploymentEnvConfig` into `get_server_public_url` and RFC 9728/8414 metadata documents.
- **OAuth 2.1 & PKCE Hardening**:
  - Enforced S256 PKCE challenge method by default on both `/oauth/authorize` and `/oauth/token` (plain PKCE disabled unless `MCP_OAUTH_ALLOW_PLAIN_PKCE=1`); added `MCP_OAUTH_STRICT_PKCE` for RFC 7636 43-128 character verifier length enforcement.
  - Added strict RFC 6749 / RFC 8252 redirect URI validation rejecting dangerous schemes, fragments, or non-loopback HTTP.
  - Whitelisted preset `chatgpt` redirect URIs to canonical OpenAI connector callback endpoints (`https://chatgpt.com/connector_platform_oauth_redirect` and dynamic connector prefixes), with preset client protection during DCR pruning.
  - Added authorization scope filtering and validation against supported scopes.
  - Enforced strict client verification by default on both authorize and token exchange endpoints via `MCP_OAUTH_STRICT_CLIENT` (defaults to 1; requires registered DCR client or preset client).
  - Added full streaming body 64KB length cap and frequency caps on Dynamic Client Registration (`/oauth/register`).
  - Restricted reverse proxy header evaluation (`X-Forwarded-*`) to trusted loopback/private proxies.
- **Cloudflare Tunnel Security**: Tunnel tokens are now passed strictly via the `TUNNEL_TOKEN` environment variable rather than exposed in `--token` command-line arguments.
- **Tray App Cleanup**: Deduplicated subprocess spawning logic into `_spawn_process()` in `BaseTrayApp` and safely handled POSIX platforms where `win32con` is absent.
- **Scaffold Templates**: Cleaned up duplicated dependencies in scaffolded `pyproject.toml`, updated unit test templates to use FastMCP public `list_tools()` API, and expanded `.env.example`.

### Fixed
- Fixed POSIX import crash when loading `tray.py` without Windows-specific dependencies.
- Fixed POSIX subprocess invocation by replacing bare `subprocess.CREATE_NO_WINDOW` with `getattr(subprocess, "CREATE_NO_WINDOW", 0)`.
- Fixed `typing.get_type_hints` failure on `oauth_authorize_endpoint` by importing `Callable` from `collections.abc`.
- Fixed Windows architecture detection in `mcp-server-core download-cloudflared` to properly distinguish 32-bit x86, AMD64, and gracefully fallback ARM64 to AMD64 emulation.
- Fixed `release.bat` to eliminate hardcoded absolute paths, include `uv.lock`, and prevent accidental staging of sensitive `.env` files.

## [0.5.0] - 2026-11-10

- Initial standardized modular architecture release with FastMCP integration, Cloudflare Named Tunnel supervisor, Windows System Tray, and OAuth 2.1.
