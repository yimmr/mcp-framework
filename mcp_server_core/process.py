"""Universal Process & Lifecycle Manager for MCP Services.

Provides unified process management, port inspection, single-instance verification,
and clean termination for both CLI and GUI desktop runners.
"""
from __future__ import annotations

import logging
import os
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

from .env import get_runtime_dir

logger = logging.getLogger(__name__)

if sys.platform == "win32":
    import win32api
    import win32con
    import win32event
    import win32process
    import winerror


def is_pid_alive(pid: int) -> bool:
    """Check if a process with given PID is currently active."""
    if pid <= 0:
        return False
    if sys.platform == "win32":
        try:
            handle = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                try:
                    code = win32process.GetExitCodeProcess(handle)
                    return code == 259  # STILL_ACTIVE
                finally:
                    win32api.CloseHandle(handle)
        except Exception as e:
            if getattr(e, "winerror", None) == getattr(winerror, "ERROR_ACCESS_DENIED", 5):
                return True
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except PermissionError:
            return True
        except OSError:
            return False
    return False


def find_pid_by_port(port: int) -> int | None:
    """Inspect local port and extract listening process PID."""
    if sys.platform == "win32":
        try:
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            out = subprocess.check_output(
                ["netstat", "-ano"],
                text=True,
                errors="replace",
                creationflags=creationflags,
            )
            for line in out.strip().splitlines():
                if "LISTENING" in line and f":{port}" in line:
                    parts = line.split()
                    if len(parts) >= 5 and parts[-1] != "0":
                        local_addr = parts[1]
                        if local_addr.endswith(f":{port}") or local_addr.rsplit(":", 1)[-1] == str(port):
                            return int(parts[-1])
        except Exception:
            pass
    else:
        try:
            out = subprocess.check_output(
                ["lsof", "-t", f"-iTCP:{port}", "-sTCP:LISTEN"],
                text=True,
                errors="replace",
            )
            for line in out.strip().splitlines():
                if line.strip().isdigit():
                    return int(line.strip())
        except Exception:
            pass

        # Fallback to ss -tlpn if lsof is missing (e.g. minimal Linux containers)
        try:
            out = subprocess.check_output(
                ["ss", "-tlpn"],
                text=True,
                errors="replace",
            )
            for line in out.splitlines():
                if f":{port} " in line or f":{port}" in line:
                    match = re.search(r"pid=(\d+)", line)
                    if match:
                        return int(match.group(1))
        except Exception:
            pass
    return None


def is_port_in_use(port: int) -> bool:
    """Fast socket check whether local port is bound (IPv4 / IPv6)."""
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


def is_mcp_or_related_process(pid: int) -> bool:
    """Verify whether a PID belongs to an MCP related process (python, uvicorn, mcp, cloudflared)."""
    if pid <= 0:
        return False
    try:
        if sys.platform == "win32":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            res = subprocess.run(
                ["tasklist", "/fi", f"pid eq {pid}", "/fo", "csv", "/nh"],
                capture_output=True,
                text=True,
                errors="replace",
                creationflags=creationflags,
                timeout=2.0,
            )
            stdout = res.stdout.lower()
            return any(k in stdout for k in ("python", "uvicorn", "mcp", "cloudflared"))
        else:
            cmdline_path = Path(f"/proc/{pid}/cmdline")
            if cmdline_path.exists():
                cmd = cmdline_path.read_text(errors="replace").lower()
                return any(k in cmd for k in ("python", "uvicorn", "mcp", "cloudflared"))
            res = subprocess.run(
                ["ps", "-p", str(pid), "-o", "command="],
                capture_output=True,
                text=True,
                timeout=2.0,
            )
            cmd = res.stdout.lower()
            return any(k in cmd for k in ("python", "uvicorn", "mcp", "cloudflared"))
    except Exception as e:
        logger.warning("Failed to verify process identity for PID %s: %s", pid, e)
        return False


def read_pid_from_files(runtime_dir: Path, root_dir: Path, filename: str) -> int | None:
    """Read first valid PID from candidate files in runtime_dir and root_dir."""
    pids = read_pids_from_files(runtime_dir, root_dir, filename)
    return pids[0] if pids else None


def read_pids_from_files(runtime_dir: Path, root_dir: Path, filename: str) -> list[int]:
    """Read all unique valid PIDs from candidate files in runtime_dir and root_dir."""
    found: list[int] = []
    for p_file in [runtime_dir / filename, root_dir / filename]:
        if p_file.exists():
            try:
                pid = int(p_file.read_text().strip())
                if pid > 0 and pid != os.getpid() and pid not in found:
                    found.append(pid)
            except Exception:
                pass
    return found


def cleanup_pid_files(runtime_dir: Path, root_dir: Path, filename: str) -> None:
    """Unlink candidate PID files in runtime_dir and root_dir."""
    for p_file in [runtime_dir / filename, root_dir / filename]:
        if p_file.exists():
            try:
                p_file.unlink()
            except Exception:
                pass


def kill_pid(pid: int, timeout: float = 3.0, check_identity: bool = True) -> bool:
    """Terminate a process and all its subprocesses by PID cleanly after identity check."""
    if pid <= 0 or pid == os.getpid():
        return False
    if check_identity and not is_mcp_or_related_process(pid):
        logger.warning("PID %s does not appear to be an MCP related process; skipping kill", pid)
        return False
    if sys.platform == "win32":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            res = subprocess.run(
                ["taskkill", "/f", "/t", "/pid", str(pid)],
                capture_output=True,
                timeout=timeout,
                creationflags=creationflags,
            )
            return res.returncode == 0
        except Exception:
            return False
    else:
        try:
            import signal
            try:
                pgid = os.getpgid(pid)
                if pgid != os.getpgrp():
                    os.killpg(pgid, signal.SIGKILL)
                else:
                    os.kill(pid, signal.SIGKILL)
            except Exception:
                os.kill(pid, signal.SIGKILL)
            return True
        except Exception:
            return False


def check_service_status(
    port: int,
    root_dir: Path,
    mutex_name: str | None = None,
    runtime_dir_name: str | None = None,
) -> tuple[bool, str, int | None]:
    """Check whether MCP service is already active, starting, or listening.

    Returns (is_active, mode_description, pid).
    """
    runtime_dir = get_runtime_dir(root_dir, runtime_dir_name=runtime_dir_name)
    in_use = is_port_in_use(port)
    pid = find_pid_by_port(port) if in_use else None

    # 1. Check if port is in use
    if in_use:
        for t_file in [runtime_dir / ".tray.pid", root_dir / ".tray.pid"]:
            if t_file.exists():
                try:
                    t_pid = int(t_file.read_text().strip())
                    if is_pid_alive(t_pid):
                        return True, "系统托盘常驻模式 (Tray App)", t_pid
                except Exception:
                    pass
        return True, "控制台 / 后台服务模式", pid

    # 2. Check tray process PID (even during initial startup before port opens)
    for t_file in [runtime_dir / ".tray.pid", root_dir / ".tray.pid"]:
        if t_file.exists():
            try:
                t_pid = int(t_file.read_text().strip())
                if is_pid_alive(t_pid):
                    return True, "系统托盘常驻模式 (启动就绪中)", t_pid
            except Exception:
                pass

    # 3. Check server process PID
    for s_file in [runtime_dir / ".server.pid", root_dir / ".server.pid"]:
        if s_file.exists():
            try:
                s_pid = int(s_file.read_text().strip())
                if is_pid_alive(s_pid):
                    return True, "核心服务进程 (启动就绪中)", s_pid
            except Exception:
                pass

    # 4. Check Named Mutex on Windows if provided
    if mutex_name and sys.platform == "win32":
        try:
            h_mutex = win32event.OpenMutex(win32event.SYNCHRONIZE, False, mutex_name)
            if h_mutex:
                win32api.CloseHandle(h_mutex)
                return True, "系统托盘常驻模式 (互斥锁已占用)", None
        except Exception:
            pass

    return False, "", None


def kill_stale_server_process(port: int, root_dir: Path, runtime_dir_name: str | None = None) -> list[int]:
    """Terminate any stale local server processes listening on port without stopping the tunnel.

    Returns list of killed PIDs.
    """
    runtime_dir = get_runtime_dir(root_dir, runtime_dir_name=runtime_dir_name)
    killed = []

    server_pids = read_pids_from_files(runtime_dir, root_dir, ".server.pid")
    for spid in server_pids:
        if kill_pid(spid, check_identity=True):
            killed.append(spid)
    cleanup_pid_files(runtime_dir, root_dir, ".server.pid")

    port_pid = find_pid_by_port(port)
    if port_pid and port_pid not in killed:
        # Process listening on configured port is already confirmed by port binding
        if kill_pid(port_pid, check_identity=False):
            killed.append(port_pid)

    return killed


def stop_mcp_service(port: int, root_dir: Path, runtime_dir_name: str | None = None) -> dict[str, Any]:
    """Complete shutdown of server, tray app, port listeners, and tunnel.

    Returns summary of stopped components and killed PIDs.
    """
    runtime_dir = get_runtime_dir(root_dir, runtime_dir_name=runtime_dir_name)
    killed_pids: list[int] = []

    # 1. Stop tray app if running
    tray_pids = read_pids_from_files(runtime_dir, root_dir, ".tray.pid")
    for tpid in tray_pids:
        if kill_pid(tpid, check_identity=True):
            killed_pids.append(tpid)
    cleanup_pid_files(runtime_dir, root_dir, ".tray.pid")

    # 2. Stop server PID
    server_pids = read_pids_from_files(runtime_dir, root_dir, ".server.pid")
    for spid in server_pids:
        if kill_pid(spid, check_identity=True):
            killed_pids.append(spid)
    cleanup_pid_files(runtime_dir, root_dir, ".server.pid")

    # 3. Kill any process listening on the target port
    port_pid = find_pid_by_port(port)
    if port_pid and port_pid not in killed_pids:
        # Verified port listener: bypass image name check
        if kill_pid(port_pid, check_identity=False):
            killed_pids.append(port_pid)

    # 4. Stop tunnel if no other service is active
    tunnel_stopped = False
    try:
        from .tunnel import stop_tunnel_if_no_mcp
        tunnel_stopped = stop_tunnel_if_no_mcp(candidate_ports={port})
    except Exception:
        pass

    return {
        "status": "success",
        "port": port,
        "killed_pids": killed_pids,
        "tunnel_stopped": tunnel_stopped,
    }
