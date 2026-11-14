# MCP Server Core 🚀

**Universal MCP Server Framework for Streamable HTTP ASGI, Cloudflare Tunnel, OAuth 2.1, System Tray & Process Supervisor**

Decoupled, reusable transport, lifecycle, and scaffolding foundation for FastMCP services.

[![PyPI version](https://img.shields.io/pypi/v/mcp-server-core.svg)](https://pypi.org/project/mcp-server-core/)
[![Python versions](https://img.shields.io/pypi/pyversions/mcp-server-core.svg)](https://pypi.org/project/mcp-server-core/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 📦 Features

- **⚡ Fast Project Scaffolding (`mcp-server-core init`)**: Bootstrap complete, production-ready, standardized MCP services in seconds with tray supervisor, console launcher, batch scripts, and `.env` pre-configured.
- **🌐 ASGI Streamable HTTP Transport**: Starlette + FastMCP integration supporting SSE, streaming, and atomic JSON-RPC responses.
- **🛡️ Cache-Busting & Anti-Stale Guarantees**: Built-in `NoCacheMiddleware` ensuring `Cache-Control: no-cache, no-store, must-revalidate` across all discovery and tool execution routes.
- **🔐 Embedded OAuth 2.1 Server**: Standard RFC 9728, RFC 8414, RFC 7591 (Dynamic Client Registration), and RFC 7636 PKCE S256 authorization code grant implementation for ChatGPT Connector and remote AI agents, featuring strict client whitelist protection (`MCP_OAUTH_STRICT_CLIENT="1"`), rate limiting, and sliding-window lockout defense.
- **🚇 Cloudflare Tunnel Singleton Supervisor**: Outbound named tunnel daemon lifecycle management with automated health check, heartbeat recovery, and centralized global configuration via `~/.mcp/.env`.
- **🔍 Cascading Cloudflared Discovery**: 
  1. Direct parameter `cloudflared_path`
  2. Environment variable `CLOUDFLARED_PATH` or `CLOUDFLARED_BIN`
  3. Global configuration in `~/.mcp/.env` or local `.env` (`CLOUDFLARED_PATH=...`)
  4. Package binary directory (`mcp_server_core/bin/cloudflared.exe`)
  5. Project workspace directory (`./bin/cloudflared.exe`)
  6. User global cache directory (`~/.mcp/bin/cloudflared.exe`)
  7. System `PATH` (`shutil.which`)
  8. Automated download via `mcp-server-core download-cloudflared`
- **🖥️ System Tray Supervisor (`BaseTrayApp`)**: Clean Windows tray app supporting dynamic High-DPI icon drawing, single-instance process supervision via Windows Job Objects, URL/Token copy menus, and custom project management actions.
- **🚀 Unified Console Launcher (`launch_service`)**: Port checking, stale PID cleanup, tunnel heartbeat monitoring, and credential masking.
- **📋 Envelope Response Model (`ToolResultListDict`)**: Dual-access envelope format supporting both dict indexing (`res["projects"]`) and list sequence operations (`len(res)`, `res[0]`).

---

## 🛠️ CLI Utilities

### 1. Rapidly Scaffold a New MCP Service
```bash
mcp-server-core init my-novel-service --port 8790 --char N --color "#0984e3"
```
Generated project structure:
```text
my-novel-service/
├── my_novel_service/
│   ├── __init__.py
│   ├── __main__.py      # python -m my_novel_service entrypoint
│   ├── config.py        # Typed DeploymentEnvConfig loader
│   ├── server.py        # FastMCP + serve_http setup
│   ├── launcher.py      # Unified console launcher with tunnel guards
│   ├── tray.py          # Windows System Tray supervisor
│   └── tools/           # Modular MCP tools
│       ├── __init__.py
│       └── system.py
├── tests/               # Built-in unit tests
│   ├── __init__.py
│   └── test_tools.py
├── start.bat            # One-click start (tray silent mode preferred)
├── stop.bat             # One-click stop
├── .env.example         # Configuration template
├── .env                 # Pre-generated secure MCP_API_KEY
├── pyproject.toml
└── README.md
```

### 2. Check Tunnel, Ports & Environment Status
```bash
mcp-server-core status
```

### 3. Download Official Cloudflared Binary
```bash
# Downloads official release for current OS & architecture
mcp-server-core download-cloudflared
```

---

## 💻 Installation & Usage

### 1. From PyPI
```bash
pip install mcp-server-core
# or with tray support
pip install "mcp-server-core[tray]"

# or using uv
uv add "mcp-server-core[tray]"
```

### 2. Python Code Usage

#### Launcher (`launcher.py`):
```python
from mcp_server_core import launch_service
from my_service.server import main as server_main

if __name__ == "__main__":
    launch_service(
        service_name="My Custom MCP Server",
        default_port=8790,
        server_runner=server_main,
    )
```

#### System Tray App (`tray_app.py`):
```python
from mcp_server_core import BaseTrayApp

class CustomTrayApp(BaseTrayApp):
    def __init__(self):
        super().__init__(
            service_name="My Custom MCP Server",
            default_port=8790,
            icon_char="M",
            icon_color="#00b894",
        )

if __name__ == "__main__":
    app = CustomTrayApp()
    app.run()
```

#### Dual-Access Response Format:
```python
from mcp_server_core import ToolResultListDict

@mcp.tool()
def list_projects() -> dict:
    projects = [{"id": 1, "name": "demo"}]
    return ToolResultListDict(projects, key="projects", status="success")
```

---

## ⚙️ Configuration & Environment Variables

All deployment and infrastructure settings can be configured via project `.env`, user global `~/.mcp/.env`, or system environment variables:

### 🌐 Centralized Global Configuration (`~/.mcp/.env`)

When running multiple MCP services on a single machine, you can centrally manage shared infrastructure settings (such as Cloudflare Tunnel token and binary path) in `~/.mcp/.env`:

```env
# ~/.mcp/.env (Shared across all MCP services on this host)
CLOUDFLARE_TUNNEL_TOKEN=eyJh...
CLOUDFLARED_PATH=
CLOUDFLARE_METRICS_PORT=20245
```

All consumer MCP services automatically inherit these settings without needing redundant tunnel tokens duplicated in each project's `.env`. Precedence order: `overrides > project .env > os.environ > ~/.mcp/.env > defaults`.

| Environment Variable | Default | Description |
| :--- | :---: | :--- |
| `MCP_PORT` | `8788` | Local HTTP / SSE bind port. |
| `MCP_HOST` | `127.0.0.1` | Local network interface host to bind. |
| `MCP_REQUIRE_AUTH` | `true` | Enforce API key or OAuth Bearer token validation. |
| `MCP_API_KEY` | *(auto-generated)* | Master security key for HTTP authentication and OAuth admin authorization. |
| `MCP_ENABLE_PUBLIC_OAUTH` | `false` | Enable RFC 9728 / RFC 8414 OAuth 2.1 metadata, DCR, and consent endpoints. |
| `MCP_ALLOW_QUERY_AUTH` | `false` | Allow token extraction via `?token=` or `?key=` query parameters (disabled by default). |
| `MCP_TUNNEL` | `true` | Automatically run Cloudflare Tunnel daemon. |
| `CLOUDFLARE_TUNNEL_TOKEN` | `""` | Cloudflare Named Tunnel token (leave empty for quick trycloudflare tunnel). |
| `MCP_SERVICE_NAME` | `mcp_service` | Identifier used for User-Agent, logs, and default titles. |
| `MCP_SERVICE_TITLE` | `None` | Display title shown on OAuth authorization pages and console banners. |
| `MCP_OAUTH_ISSUER` | *(dynamic)* | Custom authorization server issuer URL for RFC 8414 metadata. |
| `MCP_OAUTH_SCOPES` | `openid,profile,email,mcp:read,mcp:write` | Comma-separated list of supported OAuth scopes. |
| `MCP_OAUTH_REQUIRE_PKCE` | `1` | Strictly enforce RFC 7636 PKCE on authorization requests (`1`=enforced). |
| `MCP_OAUTH_STRICT_PKCE` | `0` | Strictly enforce 43–128 character code verifier length according to RFC 7636 (`1`=enforced). |
| `MCP_OAUTH_ALLOW_PLAIN_PKCE` | `0` | Allow deprecated `plain` PKCE transform method (`1`=allowed, `0`=S256 only). |
| `MCP_OAUTH_STRICT_CLIENT` | `1` | Strictly require client registration via DCR or preset connector whitelist (`1`=enforced). |
| `MCP_TRUST_PROXY_HEADERS` | `0` | Trust proxy headers from untrusted proxies (`0`=trust loopback/RFC1918 only, `1`=trust all proxies). |
| `MCP_CORS_ORIGINS` | `*` | Allowed CORS origins (comma-separated list or `*`). |
| `MCP_ALLOWED_REDIRECT_URIS` | `""` | Comma-separated additional allowed redirect URIs for OAuth clients (e.g. preset or fallback callbacks). |
| `MCP_AUTH_MAX_ATTEMPTS` | `5` | Maximum failed password attempts before triggering IP lockout. |
| `MCP_AUTH_LOCKOUT_SECS` | `900` | Security lockout duration in seconds after repeated auth failures. |
| `CLOUDFLARE_METRICS_PORT` | `20245` | Local metrics port passed to `cloudflared --metrics`. |
| `MCP_DB_PATH` | `.runtime/oauth_store.db` | SQLite database path for client registration and tokens. |
| `MCP_RUNTIME_DIR` | `.runtime` | Local directory for PID and runtime state files. |

---

## 📄 License
MIT License.
