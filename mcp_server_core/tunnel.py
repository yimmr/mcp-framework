"""Cloudflare Tunnel Manager for MCP services.

Provides both:
1. Singleton Named Tunnel Daemon management (ingress port discovery via :20245/config,
   auto start, and smart shutdown when no MCP services remain).
2. Dedicated CloudflareTunnel subprocess wrapper (Quick Tunnel or Named Tunnel).
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from .constants import (
    DEFAULT_FALLBACK_PORTS,
    DEFAULT_TUNNEL_METRICS_PORT,
)
from .env import get_global_env_file, get_global_mcp_dir

logger = logging.getLogger(__name__)

# Local metrics / management endpoint for cloudflared
TUNNEL_METRICS_HOST = "127.0.0.1"
TUNNEL_METRICS_PORT = DEFAULT_TUNNEL_METRICS_PORT
FALLBACK_PORTS = DEFAULT_FALLBACK_PORTS  # backward compatibility alias


def get_tunnel_metrics_port() -> int:
    """Dynamically get the Cloudflare metrics port from environment with fallback."""
    try:
        val = os.getenv("CLOUDFLARE_METRICS_PORT")
        if not val:
            for env_cand in [Path.cwd() / ".env", get_global_env_file()]:
                if env_cand.is_file():
                    for line in env_cand.read_text(encoding="utf-8").splitlines():
                        line = line.strip()
                        if line.startswith("CLOUDFLARE_METRICS_PORT="):
                            v = line.split("=", 1)[1].strip().strip('"').strip("'")
                            if v:
                                val = v
                                break
                if val:
                    break
        return int(val) if val else DEFAULT_TUNNEL_METRICS_PORT
    except (ValueError, TypeError):
        return DEFAULT_TUNNEL_METRICS_PORT


def get_tunnel_token(
    base_dir: Path | str | None = None,
    global_env_file: Path | str | None = None,
) -> str:
    """Resolve Cloudflare Named Tunnel token from environment or configuration."""
    token = os.getenv("CLOUDFLARE_TUNNEL_TOKEN") or os.getenv("MCP_TUNNEL_TOKEN")
    if token:
        return token.strip()

    # Fallback to local .env in base_dir, current working directory, or global ~/.mcp/.env
    candidates = []
    if base_dir:
        candidates.append(Path(base_dir).resolve() / ".env")
    candidates.append(Path.cwd() / ".env")
    resolved_global = Path(global_env_file).resolve() if global_env_file else get_global_env_file()
    candidates.append(resolved_global)

    for candidate in candidates:
        if candidate.exists():
            for line in candidate.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith("CLOUDFLARE_TUNNEL_TOKEN="):
                    val = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if val:
                        return val
                elif line.startswith("MCP_TUNNEL_TOKEN="):
                    val = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if val:
                        return val

    # Fallback to config.yaml or config/settings.yaml
    yaml_candidates = []
    if base_dir:
        yaml_candidates.extend([
            Path(base_dir).resolve() / "config.yaml",
            Path(base_dir).resolve() / "config" / "settings.yaml",
        ])
    yaml_candidates.extend([
        Path.cwd() / "config.yaml",
        Path.cwd() / "config" / "settings.yaml",
        resolved_global.parent / "config.yaml",
        resolved_global.parent / "config" / "settings.yaml",
    ])

    for candidate in yaml_candidates:
        if candidate.exists():
            try:
                import yaml
                data = yaml.safe_load(candidate.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    mcp_sec = data.get("mcp")
                    if isinstance(mcp_sec, dict):
                        http_sec = mcp_sec.get("http")
                        if isinstance(http_sec, dict):
                            t = http_sec.get("tunnel_token", "")
                            if t:
                                return str(t).strip()
            except Exception:
                pass

    return ""


def find_cloudflared(custom_path: str | Path | None = None) -> Path:
    """Locate cloudflared executable with cascading fallback.

    Search precedence:
    1. Direct argument `custom_path` (if provided and exists)
    2. Environment variable `CLOUDFLARED_PATH` or `CLOUDFLARED_BIN`
    3. Global config ~/.mcp/.env or local .env (CLOUDFLARED_PATH=...)
    4. Package's own bin/ directory (e.g. mcp_server_core/bin/cloudflared.exe)
    5. Current workspace root bin/ directory (e.g. ./bin/cloudflared.exe)
    6. User global cache directory (~/.mcp/bin/cloudflared.exe)
    7. System PATH (shutil.which("cloudflared"))
    """
    exe_name = "cloudflared.exe" if os.name == "nt" else "cloudflared"

    # 1. Direct argument
    if custom_path:
        cp = Path(custom_path).resolve()
        if cp.is_file() and cp.exists():
            return cp
        if cp.is_dir() and (cp / exe_name).exists():
            return (cp / exe_name).resolve()

    # 2. Environment variable
    env_path = os.getenv("CLOUDFLARED_PATH") or os.getenv("CLOUDFLARED_BIN")
    if env_path:
        ep = Path(env_path).resolve()
        if ep.is_file() and ep.exists():
            return ep
        if ep.is_dir() and (ep / exe_name).exists():
            return (ep / exe_name).resolve()

    # 3. Global ~/.mcp/.env or local .env
    for env_cand in [Path.cwd() / ".env", get_global_env_file()]:
        if env_cand.is_file():
            try:
                for line in env_cand.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line.startswith(("CLOUDFLARED_PATH=", "CLOUDFLARED_BIN=")):
                        val = line.split("=", 1)[1].strip().strip('"').strip("'")
                        if val:
                            ep = Path(val).resolve()
                            if ep.is_file() and ep.exists():
                                return ep
                            if ep.is_dir() and (ep / exe_name).exists():
                                return (ep / exe_name).resolve()
            except Exception:
                pass

    # 4. Package's own directory (like npm dependency directory)
    package_dir = Path(__file__).resolve().parent
    pkg_candidates = [
        package_dir / "bin" / exe_name,
        package_dir.parent / "bin" / exe_name,
    ]
    for c in pkg_candidates:
        if c.is_file() and c.exists():
            return c.resolve()

    # 5. Project workspace directory
    proj_candidates = [
        Path.cwd() / "bin" / exe_name,
        Path.cwd() / exe_name,
    ]
    for c in proj_candidates:
        if c.is_file() and c.exists():
            return c.resolve()

    # 6. User global cache directory
    user_cache = get_global_mcp_dir() / "bin" / exe_name
    if user_cache.is_file() and user_cache.exists():
        return user_cache.resolve()

    # 7. System PATH
    which = shutil.which("cloudflared")
    if which:
        return Path(which).resolve()

    raise FileNotFoundError(
        f"cloudflared executable ({exe_name}) not found!\n"
        f"Searched in:\n"
        f"  - CLOUDFLARED_PATH environment variable\n"
        f"  - Config in .env or ~/.mcp/.env\n"
        f"  - Package directory: {package_dir / 'bin'}\n"
        f"  - Workspace directory: {Path.cwd() / 'bin'}\n"
        f"  - User cache: {get_global_mcp_dir() / 'bin'}\n"
        f"  - System PATH\n"
        f"Please configure CLOUDFLARED_PATH in .env / ~/.mcp/.env or run: mcp-server-core download-cloudflared"
    )


def is_cloudflared_available(custom_path: str | Path | None = None) -> bool:
    """Check if cloudflared binary is accessible."""
    try:
        bin_path = find_cloudflared(custom_path)
        return bin_path.exists()
    except Exception:
        return False


def is_port_listening(port: int) -> bool:
    """Fast socket check whether a local port is currently listening (IPv4/IPv6)."""
    for host in ("127.0.0.1", "::1"):
        try:
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                if s.connect_ex((host, port)) == 0:
                    return True
        except Exception:
            pass
    return False


def get_cloudflare_ingress_ports(fallback_ports: set[int] | list[int] | None = None) -> set[int]:
    """Dynamically fetch all local service ports configured in Cloudflare Zero Trust Dashboard
    for this tunnel directly via the cloudflared local management endpoint.
    """
    default_ports = set(fallback_ports) if fallback_ports is not None else set(DEFAULT_FALLBACK_PORTS)
    ports: set[int] = set()
    metrics_port = get_tunnel_metrics_port()
    url = f"http://{TUNNEL_METRICS_HOST}:{metrics_port}/config"
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=0.8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for item in data.get("config", {}).get("ingress", []):
                srv = item.get("service", "")
                if srv.startswith(("http://", "https://", "tcp://")):
                    p = urlparse(srv).port
                    if p:
                        ports.add(p)
    except Exception:
        return default_ports

    return ports or default_ports


def _platform_running(exe_name: str) -> bool:
    """Internal helper to check if a process by executable name is running."""
    try:
        if sys.platform == "win32":
            win_name = exe_name if exe_name.lower().endswith(".exe") else f"{exe_name}.exe"
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            res = subprocess.run(
                ["tasklist", "/fi", f"imagename eq {win_name}"],
                capture_output=True,
                text=True,
                errors="replace",
                creationflags=creationflags,
            )
            return win_name.lower() in res.stdout.lower()
        else:
            base_name = exe_name[:-4] if exe_name.lower().endswith(".exe") else exe_name
            res = subprocess.run(
                ["pgrep", "-x", base_name],
                capture_output=True,
                text=True,
            )
            return res.returncode == 0
    except Exception as e:
        logger.warning("Error checking process %s status: %s", exe_name, e)
        return False


def is_tunnel_running() -> bool:
    """Check if cloudflared is currently running on the system."""
    return _platform_running("cloudflared")


def ensure_tunnel_running(
    token: str | None = None,
    cloudflared_path: str | Path | None = None,
    metrics_port: int | None = None,
) -> bool:
    """Ensure the Cloudflare Named Tunnel daemon is running. Starts it if not already active."""
    if is_tunnel_running():
        return True

    resolved_token = (token or get_tunnel_token()).strip()
    if not resolved_token:
        return False

    exe = find_cloudflared(cloudflared_path)
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    resolved_metrics_port = metrics_port or get_tunnel_metrics_port()
    cmd = [
        str(exe),
        "tunnel",
        "--metrics",
        f"{TUNNEL_METRICS_HOST}:{resolved_metrics_port}",
        "run",
        "--protocol",
        "http2",
    ]
    env = {**os.environ, "TUNNEL_TOKEN": resolved_token}
    subprocess.Popen(
        cmd,
        cwd=str(exe.parent),
        env=env,
        creationflags=creationflags,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.0)
    return True


def stop_tunnel_if_no_mcp(candidate_ports: set[int] | list[int] | None = None) -> bool:
    """Stop cloudflared if no local MCP services configured in Cloudflare are listening.

    Returns True if tunnel was stopped, False if other services are still active.
    """
    ingress_ports = get_cloudflare_ingress_ports(fallback_ports=candidate_ports)

    for port in ingress_ports:
        if is_port_listening(port):
            return False

    try:
        if sys.platform == "win32":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            subprocess.run(
                ["taskkill", "/f", "/im", "cloudflared.exe"],
                capture_output=True,
                creationflags=creationflags,
                timeout=2.0,
            )
        else:
            subprocess.run(
                ["pkill", "-x", "cloudflared"],
                capture_output=True,
                timeout=2.0,
            )
    except Exception as e:
        logger.warning("Failed to stop cloudflared process: %s", e)
    return True


class CloudflareTunnel:
    """Manages cloudflared subprocess to create a secure public HTTPS endpoint."""

    def __init__(
        self,
        local_port: int = 8788,
        local_host: str = "127.0.0.1",
        cloudflared_path: str | Path | None = None,
        tunnel_token: str | None = None,
        public_url: str | None = None,
        cloudflared_bin: str | Path | None = None,
        metrics_port: int | None = None,
    ) -> None:
        self.local_port = local_port
        self.local_host = local_host
        self.tunnel_token = tunnel_token.strip() if tunnel_token else None
        bin_target = cloudflared_bin or cloudflared_path
        self.cloudflared_bin = Path(bin_target).resolve() if bin_target and Path(bin_target).is_file() else find_cloudflared(bin_target)
        self.metrics_port = metrics_port or get_tunnel_metrics_port()
        self.process: subprocess.Popen | None = None
        self.public_url: str | None = public_url
        self._stop_event = threading.Event()
        self._listener_thread: threading.Thread | None = None

    def start(self, on_url_ready: Callable[[str], None] | None = None, timeout: float = 30.0) -> str:
        """Start cloudflared tunnel and wait until public HTTPS URL or connection is detected."""
        target_url = f"http://{self.local_host}:{self.local_port}"

        env = dict(os.environ)
        if self.tunnel_token:
            cmd = [
                str(self.cloudflared_bin),
                "tunnel",
                "--metrics",
                f"127.0.0.1:{self.metrics_port}",
                "run",
                "--protocol",
                "http2",
            ]
            env["TUNNEL_TOKEN"] = self.tunnel_token
        else:
            cmd = [
                str(self.cloudflared_bin),
                "tunnel",
                "--metrics",
                f"127.0.0.1:{self.metrics_port}",
                "--url",
                target_url,
                "--no-autoupdate",
                "--protocol",
                "http2",
            ]

        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0

        self.process = subprocess.Popen(
            cmd,
            cwd=str(self.cloudflared_bin.parent),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=creationflags,
        )

        ready_event = threading.Event()

        def _reader():
            quick_pattern = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")
            try:
                while not self._stop_event.is_set() and self.process and self.process.poll() is None:
                    line = self.process.stdout.readline() if self.process and self.process.stdout else ""
                    if not line:
                        break

                    if self.tunnel_token:
                        if "Registered tunnel connection" in line or "Updated to new configuration" in line:
                            if not self.public_url:
                                self.public_url = os.getenv("TUNNEL_PUBLIC_URL", "") or os.getenv("MCP_PORTAL_URL", "") or ""
                            ready_event.set()
                            if on_url_ready:
                                on_url_ready(self.public_url)
                    else:
                        match = quick_pattern.search(line)
                        if match and not self.public_url:
                            self.public_url = match.group(0).strip()
                            ready_event.set()
                            if on_url_ready:
                                on_url_ready(self.public_url)
            finally:
                # Signal waiter immediately if reader terminates (e.g. process crash or EOF)
                ready_event.set()

        self._listener_thread = threading.Thread(target=_reader, daemon=True)
        self._listener_thread.start()

        ready_event.wait(timeout=timeout)
        if not self.public_url:
            if self.process and self.process.poll() is not None:
                raise RuntimeError(f"cloudflared process exited unexpectedly with code {self.process.returncode}")
            raise TimeoutError(f"Timed out after {timeout}s waiting for Cloudflare Tunnel connection.")

        return self.public_url or ""

    def stop(self) -> None:
        """Stop the tunnel process safely."""
        self._stop_event.set()
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=3)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass
            self.process = None


def get_public_tunnel_url(default: str = "") -> str:
    """Resolve public tunnel URL from environment or configuration."""
    url = os.getenv("PUBLIC_BASE_URL") or os.getenv("TUNNEL_PUBLIC_URL")
    if url:
        return url.strip()
    try:
        from .env import DeploymentEnvConfig
        cfg = DeploymentEnvConfig.load()
        if cfg.upstream_url:
            return cfg.upstream_url.strip()
        if cfg.portal_url:
            return cfg.portal_url.strip()
    except Exception:
        pass
    return default


def check_tunnel_health(
    public_url: str = "",
    timeout: float = 5.0,
    user_agent: str | None = None,
    service_name: str | None = None,
) -> bool:
    """Perform an HTTP GET check against the public tunnel health endpoint."""
    url = (public_url or get_public_tunnel_url()).strip().rstrip("/")
    if not url:
        return False
    health_url = url if url.endswith("/health") else f"{url}/health"
    if not user_agent:
        ua_name = service_name or os.getenv("SERVICE_NAME") or os.getenv("MCP_SERVICE_NAME") or "mcp-server"
        user_agent = f"{ua_name}-Tunnel-Heartbeat/1.0"
    try:
        req = urllib.request.Request(
            health_url,
            headers={"User-Agent": user_agent},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = getattr(resp, "status", None) or getattr(resp, "code", None)
            if code is None and hasattr(resp, "getcode"):
                code = resp.getcode()
            if code is None:
                code = 200
            return 200 <= int(code) < 400
    except urllib.error.HTTPError as e:
        return 200 <= e.code < 400
    except Exception:
        return False


def restart_tunnel() -> bool:
    """Force restart the Cloudflare Named Tunnel daemon to recover broken connections."""
    try:
        if sys.platform == "win32":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            subprocess.run(
                ["taskkill", "/f", "/im", "cloudflared.exe"],
                capture_output=True,
                creationflags=creationflags,
                timeout=2.0,
            )
        else:
            subprocess.run(
                ["pkill", "-x", "cloudflared"],
                capture_output=True,
                timeout=2.0,
            )
    except Exception as e:
        logger.warning("Failed to kill cloudflared for restart: %s", e)
    time.sleep(1.0)
    return ensure_tunnel_running()


class TunnelHeartbeatMonitor:
    """Periodic background heartbeat probe that verifies public tunnel health and automatically heals if broken."""

    def __init__(
        self,
        public_url: str = "",
        check_interval: float = 30.0,
        max_consecutive_failures: int = 3,
        on_heal: Callable[[], None] | None = None,
        user_agent: str | None = None,
        service_name: str | None = None,
    ) -> None:
        self.public_url = (public_url or get_public_tunnel_url()).strip().rstrip("/")
        self.check_interval = max(5.0, check_interval)
        self.max_consecutive_failures = max(1, max_consecutive_failures)
        self.on_heal = on_heal
        self.user_agent = user_agent
        self.service_name = service_name
        self.consecutive_failures = 0
        self.last_check_time: float = 0.0
        self.last_success_time: float = 0.0
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def probe_now(self, timeout: float = 5.0) -> bool:
        """Run a synchronous health probe right now."""
        self.last_check_time = time.time()
        is_healthy = check_tunnel_health(
            self.public_url,
            timeout=timeout,
            user_agent=self.user_agent,
            service_name=self.service_name,
        )
        if is_healthy:
            self.consecutive_failures = 0
            self.last_success_time = time.time()
        else:
            self.consecutive_failures += 1
        return is_healthy

    def trigger_self_heal(self) -> bool:
        """Self-heal by terminating and relaunching the Cloudflare tunnel daemon."""
        restarted = restart_tunnel()
        if self.on_heal:
            try:
                self.on_heal()
            except Exception:
                pass
        self.consecutive_failures = 0
        return restarted

    def _run_loop(self) -> None:
        self._stop_event.wait(5.0)
        while not self._stop_event.is_set():
            healthy = self.probe_now()
            if not healthy and self.consecutive_failures >= self.max_consecutive_failures:
                self.trigger_self_heal()
            self._stop_event.wait(self.check_interval)

    def start(self) -> None:
        """Start the background heartbeat monitor thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, name="tunnel-heartbeat", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the heartbeat monitor thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None


def start_tunnel_heartbeat_monitor(
    public_url: str = "",
    check_interval: float = 30.0,
    max_consecutive_failures: int = 3,
    on_heal: Callable[[], None] | None = None,
    user_agent: str | None = None,
    service_name: str | None = None,
) -> TunnelHeartbeatMonitor:
    """Start and return a global or dedicated tunnel heartbeat monitor in daemon mode."""
    monitor = TunnelHeartbeatMonitor(
        public_url=public_url,
        check_interval=check_interval,
        max_consecutive_failures=max_consecutive_failures,
        on_heal=on_heal,
        user_agent=user_agent,
        service_name=service_name,
    )
    monitor.start()
    return monitor

