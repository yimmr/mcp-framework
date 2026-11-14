"""Command-line interface for mcp-server-core framework.

Provides:
- `mcp-server-core init [name]`: Scaffold a standardized production-grade MCP service repository.
- `mcp-server-core <name>`: Quick shortcut to scaffold directly (npx-style).
- `mcp-server-core download-cloudflared`: Download official cloudflared binary.
- `mcp-server-core status`: Check tunnel, ports, and cloudflared environment.
"""
from __future__ import annotations

import argparse
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

from .constants import __version__


# ============================================================================
# Templates for Standardized MCP Service Repository
# ============================================================================

PYPROJECT_TEMPLATE = """[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "{pkg_name}"
version = "0.1.0"
description = "{service_title} - Built with mcp-server-core"
readme = "README.md"
requires-python = ">=3.10"
dependencies = [
    "mcp-server-core[tray]>={core_version}",
]

[project.scripts]
{service_slug} = "{pkg_name}.launcher:main"
{service_slug}-tray = "{pkg_name}.tray:main"

[tool.setuptools.packages.find]
where = ["."]
include = ["{pkg_name}*"]
"""

GITIGNORE_TEMPLATE = """__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
.env
.venv
env/
venv/
.runtime/
.idea/
.vscode/

# Binary tools & external downloads
bin/
*.exe

# Local databases & runtime artifacts
*.db
*.sqlite
*.sqlite3
*.pid
*.log
"""

PKG_INIT_PY_TEMPLATE = '''"""Package for {service_title}."""
from {pkg_name}.server import mcp, create_mcp_server

__all__ = ["mcp", "create_mcp_server"]
'''

CONFIG_PY_TEMPLATE = '''"""Configuration loader for {service_title}."""
from pathlib import Path
from mcp_server_core import DeploymentEnvConfig

ROOT_DIR = Path(__file__).resolve().parents[1]


def get_config() -> DeploymentEnvConfig:
    """Load deployment environment configuration."""
    return DeploymentEnvConfig.load(ROOT_DIR)
'''

TOOLS_INIT_PY_TEMPLATE = '''"""Modular MCP Tools collection for {service_title}."""
from mcp.server.fastmcp import FastMCP
from {pkg_name}.tools.system import register_system_tools


def register_all_tools(mcp: FastMCP) -> None:
    """Register all tools into FastMCP server instance."""
    register_system_tools(mcp)
'''

TOOLS_SYSTEM_PY_TEMPLATE = '''"""System and diagnostic MCP tools."""
from typing import Any
from mcp.server.fastmcp import FastMCP
from mcp_server_core import ToolResultListDict


def register_system_tools(mcp: FastMCP) -> None:
    """Register system and diagnostic tools."""

    @mcp.tool()
    def ping(message: str = "pong") -> dict[str, Any]:
        """Verify service health and tool connectivity."""
        return {{
            "status": "healthy",
            "service": "{service_title}",
            "echo": message,
        }}

    @mcp.tool()
    def list_capabilities() -> dict[str, Any]:
        """List service capabilities using structured ToolResultListDict envelope."""
        items = [
            {{"name": "health", "description": "Liveness and readiness probes"}},
            {{"name": "tools", "description": "Modular MCP tool registration"}},
        ]
        return ToolResultListDict(items, key="capabilities")
'''

SERVER_PY_TEMPLATE = '''"""MCP Server application for {service_title}."""
from __future__ import annotations

import sys
from mcp.server.fastmcp import FastMCP
from mcp_server_core import run_mcp_server

from {pkg_name}.config import ROOT_DIR, get_config
from {pkg_name}.tools import register_all_tools


def create_mcp_server() -> FastMCP:
    """Instantiate and configure FastMCP server."""
    env_cfg = get_config()
    title = getattr(env_cfg, "service_title", None) or "{service_title}"
    server = FastMCP(title)
    register_all_tools(server)
    return server


mcp = create_mcp_server()


def main() -> None:
    """Universal MCP Server Runner entrypoint with CLI argument parsing."""
    try:
        run_mcp_server(
            server=mcp,
            base_dir=ROOT_DIR,
        )
    except (KeyboardInterrupt, SystemExit):
        pass


if __name__ == "__main__":
    main()
'''

LAUNCHER_PY_TEMPLATE = '''"""Console Launcher for {service_title} with Tunnel & Single-Instance Guards."""
from mcp_server_core import launch_service
from {pkg_name}.config import ROOT_DIR, get_config
from {pkg_name}.server import main as server_main


def main() -> None:
    """Launch the service in console mode."""
    cfg = get_config()
    try:
        launch_service(
            default_port=cfg.port or {port},
            server_runner=server_main,
            root_dir=ROOT_DIR,
        )
    except (KeyboardInterrupt, SystemExit):
        pass


if __name__ == "__main__":
    main()
'''

TRAY_PY_TEMPLATE = '''"""System Tray Application for {service_title}."""
from mcp_server_core import BaseTrayApp
from {pkg_name}.config import ROOT_DIR, get_config


class ServiceTrayApp(BaseTrayApp):
    def __init__(self):
        cfg = get_config()
        super().__init__(
            base_dir=ROOT_DIR,
            default_port=cfg.port or {port},
            icon_char="{icon_text}",
            icon_color="{icon_color}",
            server_module="{pkg_name}.server",
        )


def main() -> None:
    """Launch the service in system tray mode."""
    try:
        app = ServiceTrayApp()
        app.run()
    except (KeyboardInterrupt, SystemExit):
        pass


if __name__ == "__main__":
    main()
'''

MAIN_PY_TEMPLATE = '''"""Unified package CLI entrypoint: python -m {pkg_name}"""
import sys

if "--tray" in sys.argv:
    from {pkg_name}.tray import main
else:
    from {pkg_name}.launcher import main

if __name__ == "__main__":
    main()
'''

TEST_TOOLS_PY_TEMPLATE = '''"""Unit tests for {service_title}."""
import unittest
from mcp.server.fastmcp import FastMCP
from {pkg_name}.tools.system import register_system_tools


class TestTools(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.mcp = FastMCP("TestServer")
        register_system_tools(self.mcp)

    async def test_registered_tools(self):
        tools = await self.mcp.list_tools()
        tool_names = [t.name for t in tools]
        self.assertIn("ping", tool_names)


if __name__ == "__main__":
    unittest.main()
'''

START_BAT_TEMPLATE = """@echo off
chcp 65001 >nul
title {service_title}

cd /d "%~dp0"

:: 检查虚拟环境与 Python 执行器
set "PYTHON_EXE="
if exist "%~dp0.venv\\Scripts\\python.exe" (
    set "PYTHON_EXE=%~dp0.venv\\Scripts\\python.exe"
) else (
    where python >nul 2>nul
    if %errorlevel% equ 0 set "PYTHON_EXE=python"
)

if "%PYTHON_EXE%"=="" (
    echo [ERROR] Python environment not found! Please run uv venv or install Python.
    pause
    exit /b 1
)

:: 启动服务（支持传递参数如 --tray 或 --show-key）
"%PYTHON_EXE%" -m {pkg_name} %*
if errorlevel 1 pause
"""

STOP_BAT_TEMPLATE = """@echo off
chcp 65001 >nul
cd /d "%~dp0"

set "PYTHON_EXE="
if exist "%~dp0.venv\\Scripts\\python.exe" (
    set "PYTHON_EXE=%~dp0.venv\\Scripts\\python.exe"
) else (
    where python >nul 2>nul
    if %errorlevel% equ 0 set "PYTHON_EXE=python"
)

if "%PYTHON_EXE%"=="" (
    echo [ERROR] Python environment not found!
    exit /b 1
)

"%PYTHON_EXE%" -m {pkg_name}.launcher --stop
timeout /t 2 >nul
"""

ENV_EXAMPLE_TEMPLATE = """# ==============================================================================
# 0. MCP Service Identity & Display Title
# ==============================================================================
MCP_SERVICE_NAME={service_slug}
MCP_SERVICE_TITLE={service_title}

# ==============================================================================
# 1. Network & Security Endpoints
# ==============================================================================
MCP_PORT={port}
MCP_HOST=127.0.0.1
MCP_REQUIRE_AUTH=true
MCP_API_KEY=your_secret_api_key_here

# ==============================================================================
# 2. Cloudflare Named Tunnel (Optional)
# Tip: CLOUDFLARE_TUNNEL_TOKEN and CLOUDFLARED_PATH can also be centrally
# configured in ~/.mcp/.env to share across all local MCP services.
# ==============================================================================
CLOUDFLARE_TUNNEL_TOKEN=
CLOUDFLARED_PATH=

# Public Upstream URL (Optional, if using custom domain)
MCP_UPSTREAM_URL=

# Cloudflare Tunnel metrics port (default: 20245)
# CLOUDFLARE_METRICS_PORT=20245

# OAuth 2.1 Configuration (Optional)
# MCP_ENABLE_PUBLIC_OAUTH=false
# MCP_OAUTH_SCOPES=openid,profile,email,mcp:read,mcp:write
# MCP_ALLOWED_REDIRECT_URIS=https://chatgpt.com/connector_platform_oauth_redirect
"""

README_TEMPLATE = """# {service_title}

Standard MCP Service built with [mcp-server-core](https://pypi.org/project/mcp-server-core/).

## 📁 目录规范 (Standard Directory Structure)

```text
{project_name}/
├── {pkg_name}/                 # 核心命名包（绝非泛滥的 app/，杜绝命名污染）
│   ├── __init__.py             # 导出 mcp 与 server
│   ├── __main__.py             # python -m {pkg_name} 统一执行入口
│   ├── config.py               # 强类型配置加载器 (DeploymentEnvConfig)
│   ├── server.py               # FastMCP 实例定义与 HTTP/stdio 传输服务
│   ├── launcher.py             # 控制台运行逻辑与穿透守护
│   ├── tray.py                 # Windows 托盘监控逻辑
│   └── tools/                  # 模块化工具集合
│       ├── __init__.py         # 统一注册全部工具
│       └── system.py           # 系统状态与诊断工具示例
├── tests/                      # 开箱即用的单元测试
│   ├── __init__.py
│   └── test_tools.py
├── start.bat                   # 一键静默托盘启动
├── stop.bat                    # 一键安全关闭
├── .env.example                # 环境变量配置模板
├── .env                        # 预设安全密钥的标准配置
├── pyproject.toml              # PEP 621 标准打包规范，内置 CLI 命令
└── README.md
```

## 🚀 快速启动 (Quick Start)

> 💡 **提示**：本项目在初始化时已自动完成 `.venv` 虚拟环境创建与依赖安装，**无需再次安装，直接启动即可！**

### 启动服务
- **双击启动 (推荐)**: 直接双击运行 `start.bat`，服务将在系统托盘后台静默运行。
- **CLI 命令启动**:
  ```bash
  uv run {service_slug}          # 控制台模式
  uv run {service_slug}-tray     # 托盘模式
  ```
- **停止服务**: 双击运行 `stop.bat`，或在右下角托盘图标右键选择 **退出服务**。

### 运行测试
```bash
uv run python -m unittest discover -s tests
```

---

### 📦 跨机器重新部署 (仅当换新电脑或重新拉取源码时需要)
```bash
uv venv
uv pip install -e .
```

## 🔐 客户端配置 (MCP Client Config)

在 Claude Desktop / Cursor / VS Code 等客户端中配置此 MCP 服务：

```json
{{
  "mcpServers": {{
    "{service_slug}": {{
      "command": "python",
      "args": ["-m", "{pkg_name}", "--stdio"],
      "env": {{
        "MCP_API_KEY": "{api_key}"
      }}
    }}
  }}
}}
```

或连接 HTTP 远程端点：
- **URL**: `http://127.0.0.1:{port}/mcp`
- **Header**: `Authorization: Bearer {api_key}`

## 🛠️ 添加自定义工具 (Tools)

在 `{pkg_name}/tools/` 目录下新增 Python 模块，并在 `{pkg_name}/tools/__init__.py` 中统一调用注册即可。
"""


# ============================================================================
# 1. Scaffolding: `mcp-server-core init`
# ============================================================================

def normalize_package_name(name: str) -> str:
    """Convert arbitrary string into valid Python package name."""
    import keyword
    s = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    s = re.sub(r"^([0-9])", r"_\1", s)
    s = s.lower()
    if not s.strip("_"):
        return "mcp_service"
    if keyword.iskeyword(s):
        return f"{s}_mcp"
    return s


def install_dependencies(target_dir: Path) -> bool:
    """Create virtual environment and install project in editable mode."""
    uv_bin = shutil.which("uv")
    if uv_bin:
        print("\n[*] Initializing virtual environment with uv...")
        try:
            res_venv = subprocess.run([uv_bin, "venv"], cwd=target_dir, capture_output=True, text=True)
            if res_venv.returncode != 0:
                print(f"[!] Warning creating .venv: {res_venv.stderr.strip()}")
            else:
                print("  + Virtual environment created (.venv)")

            print("[*] Installing project dependencies with uv pip install -e . ...")
            res_pip = subprocess.run(
                [uv_bin, "pip", "install", "-e", "."],
                cwd=target_dir,
                capture_output=True,
                text=True,
            )
            if res_pip.returncode != 0:
                print(f"[!] Warning installing dependencies: {res_pip.stderr.strip()}")
                return False
            print("  + Dependencies installed successfully in editable mode!")
            return True
        except Exception as e:
            print(f"[!] Error during uv installation: {e}")
            return False

    # Fallback to standard python venv & pip
    py_bin = sys.executable
    print("\n[*] Initializing virtual environment with python -m venv...")
    try:
        subprocess.run([py_bin, "-m", "venv", ".venv"], cwd=target_dir, check=True)
        print("  + Virtual environment created (.venv)")

        venv_py = (
            target_dir / ".venv" / "Scripts" / "python.exe"
            if os.name == "nt"
            else target_dir / ".venv" / "bin" / "python"
        )
        print("[*] Installing project dependencies with pip install -e . ...")
        subprocess.run([str(venv_py), "-m", "pip", "install", "-e", "."], cwd=target_dir, check=True)
        print("  + Dependencies installed successfully in editable mode!")
        return True
    except Exception as e:
        print(f"[!] Error during pip installation: {e}")
        return False


def cmd_init(args: argparse.Namespace) -> int:
    """Scaffold a new standardized MCP service project."""
    is_interactive = sys.stdin.isatty() and not getattr(args, "yes", False)

    # 1. Project directory / name
    name = args.name
    if not name:
        if is_interactive:
            print("\n🚀 Welcome to MCP Server Core Scaffolding Wizard!\n")
            try:
                name_input = input("? Project directory name [my-mcp-service]: ").strip()
                name = name_input or "my-mcp-service"
            except (KeyboardInterrupt, EOFError):
                print("\n[!] Aborted.")
                return 1
        else:
            name = "my-mcp-service"

    target_dir = Path(name).resolve()
    project_name = target_dir.name
    pkg_name = normalize_package_name(project_name)

    # 2. Display title
    default_title = project_name.replace("-", " ").replace("_", " ").title()
    service_title = args.title
    if not service_title and is_interactive and not args.name:
        try:
            title_input = input(f"? Service display title [{default_title}]: ").strip()
            service_title = title_input or default_title
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Aborted.")
            return 1
    elif not service_title:
        service_title = default_title

    service_slug = project_name.lower().replace("_", "-")

    # 3. Port
    port_val = getattr(args, "port", None)
    if port_val is not None:
        port = int(port_val)
    elif is_interactive and not args.name:
        try:
            port_input = input("? Service port [8788]: ").strip()
            port = int(port_input) if port_input else 8788
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Aborted.")
            return 1
    else:
        port = 8788

    # 4. Icon character
    default_char = project_name[0].upper() if project_name else "M"
    icon_text = args.char
    if not icon_text and is_interactive and not args.name:
        try:
            char_input = input(f"? Tray icon character [{default_char}]: ").strip()
            icon_text = char_input or default_char
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Aborted.")
            return 1
    elif not icon_text:
        icon_text = default_char

    icon_color = args.color or "#00b894"

    # 5. Dependency installation
    if getattr(args, "no_install", False):
        auto_install = False
    elif getattr(args, "install", False) or getattr(args, "yes", False):
        auto_install = True
    elif is_interactive:
        try:
            inst_input = input("? Initialize virtual environment and install dependencies now? [Y/n]: ").strip().lower()
            auto_install = inst_input not in ("n", "no")
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Aborted.")
            return 1
    else:
        auto_install = False

    api_key = f"sec_{secrets.token_urlsafe(24)}"

    if target_dir.exists() and not args.force:
        if any(target_dir.iterdir()):
            print(f"[ERROR] Target directory '{target_dir}' is not empty! Use --force to overwrite.")
            return 1

    print(f"\n[*] Initializing standardized MCP service in: {target_dir}")
    target_dir.mkdir(parents=True, exist_ok=True)

    pkg_dir = target_dir / pkg_name
    tools_dir = pkg_dir / "tools"
    tests_dir = target_dir / "tests"

    pkg_dir.mkdir(exist_ok=True)
    tools_dir.mkdir(exist_ok=True)
    tests_dir.mkdir(exist_ok=True)

    # Render all files
    files = {
        target_dir / "pyproject.toml": PYPROJECT_TEMPLATE.format(
            pkg_name=pkg_name,
            service_title=service_title,
            service_slug=service_slug,
            core_version=__version__,
        ),
        target_dir / ".gitignore": GITIGNORE_TEMPLATE,
        target_dir / ".env.example": ENV_EXAMPLE_TEMPLATE.format(
            port=port,
            service_slug=service_slug,
            service_title=service_title,
        ),
        target_dir / ".env": (
            f"MCP_SERVICE_NAME={service_slug}\n"
            f"MCP_SERVICE_TITLE={service_title}\n"
            f"MCP_PORT={port}\n"
            f"MCP_HOST=127.0.0.1\n"
            f"MCP_REQUIRE_AUTH=true\n"
            f"MCP_API_KEY={api_key}\n"
            f"CLOUDFLARE_TUNNEL_TOKEN=\n"
            f"CLOUDFLARED_PATH=\n"
            f"MCP_UPSTREAM_URL=\n"
        ),
        target_dir / "start.bat": START_BAT_TEMPLATE.format(
            service_title=service_title, pkg_name=pkg_name
        ),
        target_dir / "stop.bat": STOP_BAT_TEMPLATE.format(pkg_name=pkg_name),
        target_dir / "README.md": README_TEMPLATE.format(
            project_name=project_name,
            service_title=service_title,
            service_slug=service_slug,
            pkg_name=pkg_name,
            port=port,
            api_key=api_key,
        ),
        # Package files
        pkg_dir / "__init__.py": PKG_INIT_PY_TEMPLATE.format(
            service_title=service_title, pkg_name=pkg_name
        ),
        pkg_dir / "__main__.py": MAIN_PY_TEMPLATE.format(pkg_name=pkg_name),
        pkg_dir / "config.py": CONFIG_PY_TEMPLATE.format(service_title=service_title),
        pkg_dir / "server.py": SERVER_PY_TEMPLATE.format(
            service_title=service_title, service_slug=service_slug, pkg_name=pkg_name
        ),
        pkg_dir / "launcher.py": LAUNCHER_PY_TEMPLATE.format(
            service_title=service_title, port=port, pkg_name=pkg_name
        ),
        pkg_dir / "tray.py": TRAY_PY_TEMPLATE.format(
            service_title=service_title,
            port=port,
            icon_text=icon_text,
            icon_color=icon_color,
            pkg_name=pkg_name,
        ),
        # Tools files
        tools_dir / "__init__.py": TOOLS_INIT_PY_TEMPLATE.format(
            service_title=service_title, pkg_name=pkg_name
        ),
        tools_dir / "system.py": TOOLS_SYSTEM_PY_TEMPLATE.format(service_title=service_title),
        # Tests files
        tests_dir / "__init__.py": "",
        tests_dir / "test_tools.py": TEST_TOOLS_PY_TEMPLATE.format(
            service_title=service_title, pkg_name=pkg_name
        ),
    }

    for path, content in files.items():
        path.write_text(content, encoding="utf-8")
        print(f"  + Created: {path.relative_to(target_dir)}")

    # Execute dependency installation by default
    if auto_install:
        success = install_dependencies(target_dir)
        if success:
            print(f"\n[OK] Standardized project '{service_title}' is 100% ready to run!")
            print(f"\nTo launch your service:")
            print(f"  cd {name}")
            print(f"  .\\start.bat               # Windows Silent Tray mode (Double-click or run)")
            print(f"  uv run {service_slug}     # Console debug mode")
            return 0
        else:
            print(f"\n[!] Automatic dependency installation encountered issues. You can manually install via:")
            print(f"  cd {name}")
            print(f"  uv venv")
            print(f"  uv pip install -e .")
            print(f"  .\\start.bat")
            return 1

    # Only shown if user explicitly passed --no-install
    print(f"\n[OK] Standardized project '{service_title}' created successfully (--no-install).")
    print(f"\nTo manually install dependencies and run:")
    print(f"  cd {name}")
    print(f"  uv venv")
    print(f"  uv pip install -e .")
    print(f"  .\\start.bat")
    return 0


# ============================================================================
# 2. Binary Manager: `mcp-server-core download-cloudflared`
# ============================================================================

CLOUDFLARED_RELEASE_BASE = "https://github.com/cloudflare/cloudflared/releases/latest/download"


def get_cloudflared_download_info() -> tuple[str, str]:
    """Determine download URL and executable file name for current OS and architecture."""
    system = sys.platform
    machine = platform.machine().lower()

    if system == "win32":
        if "arm" in machine or "aarch64" in machine:
            # Cloudflare does not currently distribute a native Windows arm64 build; fallback to amd64 (runs under emulation on Win11 ARM64)
            return f"{CLOUDFLARED_RELEASE_BASE}/cloudflared-windows-amd64.exe", "cloudflared.exe"
        if "64" in machine:
            return f"{CLOUDFLARED_RELEASE_BASE}/cloudflared-windows-amd64.exe", "cloudflared.exe"
        return f"{CLOUDFLARED_RELEASE_BASE}/cloudflared-windows-386.exe", "cloudflared.exe"
    elif system == "darwin":
        if "arm" in machine or "aarch64" in machine:
            return f"{CLOUDFLARED_RELEASE_BASE}/cloudflared-darwin-arm64.tgz", "cloudflared"
        return f"{CLOUDFLARED_RELEASE_BASE}/cloudflared-darwin-amd64.tgz", "cloudflared"
    elif system.startswith("linux"):
        if "aarch64" in machine or "arm64" in machine:
            return f"{CLOUDFLARED_RELEASE_BASE}/cloudflared-linux-arm64", "cloudflared"
        return f"{CLOUDFLARED_RELEASE_BASE}/cloudflared-linux-amd64", "cloudflared"

    raise RuntimeError(f"Unsupported OS/architecture: {system} {machine}")


def cmd_download_cloudflared(args: argparse.Namespace) -> int:
    """Download official cloudflared binary to package bin or custom directory."""
    url, exe_name = get_cloudflared_download_info()

    if args.target:
        target_dir = Path(args.target).resolve()
    else:
        pkg_bin = Path(__file__).resolve().parent / "bin"
        try:
            pkg_bin.mkdir(parents=True, exist_ok=True)
            test_file = pkg_bin / ".write_test"
            test_file.touch()
            test_file.unlink()
            target_dir = pkg_bin
        except (PermissionError, OSError):
            target_dir = Path.home() / ".mcp" / "bin"
            target_dir.mkdir(parents=True, exist_ok=True)

    target_file = target_dir / exe_name
    print(f"[*] Downloading cloudflared for {platform.system()} ({platform.machine()})...")
    print(f"  Source: {url}")
    print(f"  Target: {target_file}")

    try:
        temp_file = target_file.with_suffix(".tmp")
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        with urllib.request.urlopen(req, timeout=30) as resp, open(temp_file, "wb") as out_file:
            total_size_header = resp.headers.get("Content-Length")
            total_size = int(total_size_header) if total_size_header else 0
            downloaded = 0
            block_size = 65536

            while True:
                chunk = resp.read(block_size)
                if not chunk:
                    break
                out_file.write(chunk)
                downloaded += len(chunk)
                if total_size > 0:
                    percent = int(downloaded * 100 / total_size)
                    downloaded_mb = downloaded / (1024 * 1024)
                    total_mb = total_size / (1024 * 1024)
                    sys.stdout.write(f"\r  Progress: {percent:3d}% [{downloaded_mb:.1f}MB / {total_mb:.1f}MB]")
                    sys.stdout.flush()

        print()
        if url.endswith((".tgz", ".tar.gz")):
            import tarfile
            with tarfile.open(temp_file, "r:gz") as tar:
                member = None
                for m in tar.getmembers():
                    if m.name == exe_name or m.name.endswith(f"/{exe_name}"):
                        member = m
                        break
                if member:
                    extracted = tar.extractfile(member)
                    if extracted:
                        if target_file.exists():
                            target_file.unlink()
                        target_file.write_bytes(extracted.read())
                    else:
                        raise RuntimeError(f"Could not extract {exe_name} from archive")
                else:
                    raise RuntimeError(f"Could not find {exe_name} inside downloaded archive {url}")
            if temp_file.exists():
                temp_file.unlink()
        else:
            if target_file.exists():
                target_file.unlink()
            temp_file.rename(target_file)

        if os.name != "nt":
            mode = os.stat(target_file).st_mode
            os.chmod(target_file, mode | 0o111)

        print(f"[OK] Downloaded cloudflared to: {target_file}")

        try:
            res = subprocess.run([str(target_file), "--version"], capture_output=True, text=True, check=True)
            print(f"[*] Version: {res.stdout.strip()}")
        except Exception as e:
            print(f"[!] Warning: Could not execute {target_file}: {e}")

        return 0
    except Exception as e:
        print(f"\n[ERROR] Failed to download cloudflared: {e}")
        return 1


# ============================================================================
# 3. Environment Inspector: `mcp-server-core status`
# ============================================================================

def cmd_status(args: argparse.Namespace) -> int:
    """Inspect environment status (cloudflared, active tunnel, listening ports)."""
    from mcp_server_core.tunnel import (
        find_cloudflared,
        is_tunnel_running,
        get_cloudflare_ingress_ports,
        is_port_listening,
    )
    from mcp_server_core.env import DeploymentEnvConfig, get_global_env_file, parse_env_file

    print("=" * 60)
    print(f"  mcp-server-core Framework Inspector (v{__version__})")
    print("=" * 60)

    # 1. Cloudflared binary
    print("\n[1] Cloudflared Binary:")
    try:
        cf_path = find_cloudflared()
        print(f"  * Status:   FOUND")
        print(f"  * Path:     {cf_path}")
        try:
            res = subprocess.run([str(cf_path), "--version"], capture_output=True, text=True, timeout=2)
            print(f"  * Version:  {res.stdout.strip()}")
        except Exception:
            pass
    except Exception as e:
        print(f"  * Status:   NOT FOUND ({e})")
        print(f"  * Tip:      Run 'mcp-server-core download-cloudflared' to install it.")

    # 2. Tunnel Status
    print("\n[2] Cloudflare Tunnel Daemon:")
    tunnel_up = is_tunnel_running()
    print(f"  * Running:  {'YES (Active)' if tunnel_up else 'NO (Inactive)'}")
    if tunnel_up:
        ingress = get_cloudflare_ingress_ports()
        print(f"  * Ingress Ports: {sorted(ingress) if ingress else 'None detected'}")

    # 3. Global Configuration (~/.mcp/.env)
    global_env = get_global_env_file()
    print(f"\n[3] Global Configuration ({global_env}):")
    if global_env.exists():
        g_vals = parse_env_file(global_env)
        has_token = bool(g_vals.get("CLOUDFLARE_TUNNEL_TOKEN") or g_vals.get("MCP_TUNNEL_TOKEN"))
        has_cf_bin = bool(g_vals.get("CLOUDFLARED_PATH") or g_vals.get("CLOUDFLARED_BIN"))
        print(f"  * Status:           FOUND")
        print(f"  * Tunnel Token:     {'Configured (masked)' if has_token else 'Not set'}")
        if has_cf_bin:
            print(f"  * Cloudflared Path: {g_vals.get('CLOUDFLARED_PATH') or g_vals.get('CLOUDFLARED_BIN')}")
    else:
        print(f"  * Status:           NOT FOUND (Optional: configure ~/.mcp/.env to share global settings)")

    # 4. Local Workspace
    print("\n[4] Current Directory (.env):")
    env_file = Path.cwd() / ".env"
    if env_file.exists():
        cfg = DeploymentEnvConfig.load(Path.cwd())
        key_status = "Configured (secret)" if cfg.api_key else "Not set"
        print(f"  * File:     {env_file}")
        print(f"  * Port:     {cfg.port}")
        print(f"  * API Key:  {key_status}")
        print(f"  * Custom Cloudflared: {cfg.cloudflared_path or 'Not specified (using auto fallback)'}")
        print(f"  * Port Listening: {is_port_listening(cfg.port)}")
    else:
        print(f"  * No .env found in current working directory ({Path.cwd()})")

    print("\n" + "=" * 60)
    return 0


# ============================================================================
# Main Dispatcher & Shortcuts
# ============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Build argument parser."""
    parser = argparse.ArgumentParser(
        prog="mcp-server-core",
        description="CLI utilities and scaffolding for mcp-server-core framework.",
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # init
    p_init = subparsers.add_parser("init", help="Scaffold a new MCP service project")
    p_init.add_argument("name", nargs="?", default=None, help="Name and directory of the new project (e.g. my-service)")
    p_init.add_argument("--port", default=None, type=int, help="Default service port (default: 8788)")
    p_init.add_argument("--title", default=None, help="Display title of the service")
    p_init.add_argument("--char", default=None, help="Tray icon letter/character (default: first letter)")
    p_init.add_argument("--color", default="#00b894", help="Tray icon background hex color (default: #00b894)")
    p_init.add_argument("--force", action="store_true", help="Force initialization in non-empty directory")
    p_init.add_argument("--install", action="store_true", default=None, help="Automatically initialize .venv and install dependencies")
    p_init.add_argument("--no-install", action="store_true", help="Skip creating .venv and installing dependencies")
    p_init.add_argument("-y", "--yes", action="store_true", help="Accept all defaults and install dependencies without prompting")
    p_init.set_defaults(func=cmd_init)

    # create (alias to init)
    p_create = subparsers.add_parser("create", help="Alias to 'init'")
    p_create.add_argument("name", nargs="?", default=None, help="Name and directory of the new project")
    p_create.add_argument("--port", default=None, type=int, help="Default service port (default: 8788)")
    p_create.add_argument("--title", default=None, help="Display title of the service")
    p_create.add_argument("--char", default=None, help="Tray icon letter/character")
    p_create.add_argument("--color", default="#00b894", help="Tray icon background hex color")
    p_create.add_argument("--force", action="store_true", help="Force initialization in non-empty directory")
    p_create.add_argument("--install", action="store_true", default=None, help="Automatically initialize .venv and install dependencies")
    p_create.add_argument("--no-install", action="store_true", help="Skip creating .venv and installing dependencies")
    p_create.add_argument("-y", "--yes", action="store_true", help="Accept all defaults and install dependencies without prompting")
    p_create.set_defaults(func=cmd_init)

    # download-cloudflared
    p_dl = subparsers.add_parser("download-cloudflared", help="Download official cloudflared binary")
    p_dl.add_argument("--target", default=None, help="Custom destination directory for cloudflared executable")
    p_dl.set_defaults(func=cmd_download_cloudflared)

    # status
    p_status = subparsers.add_parser("status", help="Inspect tunnel, binary, and service ports")
    p_status.set_defaults(func=cmd_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI main dispatcher with npx-style shortcut support."""
    args_list = list(sys.argv[1:] if argv is None else argv)

    # npx-style smart shortcut:
    # If the first argument is not a known command or flag, interpret it as `init <name>`
    known_commands = {"init", "create", "download-cloudflared", "status", "-v", "--version", "-h", "--help"}
    if args_list and not args_list[0].startswith("-") and args_list[0] not in known_commands:
        args_list = ["init"] + args_list

    parser = create_parser()

    # If no args at all, launch interactive init wizard if interactive terminal
    if not args_list:
        if sys.stdin.isatty():
            args = parser.parse_args(["init"])
            return args.func(args)
        else:
            parser.print_help()
            return 0

    args = parser.parse_args(args_list)
    if not hasattr(args, "func"):
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
