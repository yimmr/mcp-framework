"""Unified MCP Service Launcher and Process Lifecycle CLI."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Callable

from .console import configure_console_encoding
from .env import DeploymentEnvConfig, ensure_api_key
from .process import check_service_status, stop_mcp_service
from .tunnel import ensure_tunnel_running, start_tunnel_heartbeat_monitor


def launch_service(
    service_name: str | None = None,
    server_runner: Callable[[], Any] | None = None,
    default_port: int = 8788,
    root_dir: Path | str | None = None,
    mutex_name: str | None = None,
) -> None:
    """Launch an MCP service in console mode with tunnel supervisor and single-instance guards.

    Handles:
    - sys.platform Windows console UTF-8 safety
    - `--stop`: Terminate running server on port
    - `--test`: Pre-flight check and exit
    - Single-instance detection with helpful console alerts
    - Background shared Cloudflare Tunnel check & heartbeat monitor
    - Seamless delegation to server_runner with `--no-tunnel`
    """
    configure_console_encoding()

    orig_cwd = Path.cwd().resolve()
    orig_argv = list(sys.argv)
    cwd = Path(root_dir).resolve() if root_dir else orig_cwd
    os.chdir(cwd)

    try:
        env_cfg: DeploymentEnvConfig | None = None
        try:
            overrides = {"port": default_port} if not os.getenv("MCP_PORT") else {}
            env_cfg = DeploymentEnvConfig.load(cwd, overrides=overrides)
            port = env_cfg.port or default_port
            key_configured = bool(env_cfg.api_key)
            if not key_configured and env_cfg.require_auth:
                created_key = ensure_api_key(cwd)
                if created_key:
                    env_cfg.api_key = created_key
                    key_configured = True
            secret_key = env_cfg.api_key if "--show-key" in sys.argv else ("已配置（不显示密钥）" if key_configured else "未配置")
            public_endpoint = env_cfg.upstream_url or f"http://127.0.0.1:{port}/mcp"
        except Exception:
            port = default_port
            api_key_env = os.getenv("MCP_API_KEY", "")
            key_configured = bool(api_key_env)
            secret_key = api_key_env if "--show-key" in sys.argv else ("已配置（不显示密钥）" if key_configured else "未配置")
            public_endpoint = os.getenv("TUNNEL_PUBLIC_URL", f"http://127.0.0.1:{port}/mcp")

        active_service_name = service_name or (env_cfg.display_title if env_cfg else "MCP Service")
        local_endpoint = f"http://127.0.0.1:{port}/mcp"
        active_mutex = mutex_name or f"Local\\{active_service_name.replace(' ', '_')}_{port}"
        runtime_dir_name = getattr(env_cfg, "runtime_dir", None) if env_cfg else None

        if "--stop" in sys.argv:
            print(f"[*] 正在停止 {active_service_name} (端口 {port})...")
            res = stop_mcp_service(port, cwd, runtime_dir_name=runtime_dir_name)
            if res.get("killed_pids"):
                print(f"[SUCCESS] {active_service_name} 服务已成功停止 (已终结进程: {res['killed_pids']})！")
            else:
                print(f"[INFO] 未检测到端口 {port} 上正在运行的 {active_service_name} 服务。")
            sys.exit(0)

        is_running, mode_desc, running_pid = check_service_status(
            port, cwd, active_mutex, runtime_dir_name=runtime_dir_name
        )
        if is_running:
            print("\n" + "=" * 70)
            print(f"  【提示】{active_service_name} 服务已在运行中（或正在启动），请勿重复启动！")
            print("=" * 70)
            print(f"  * 运行模式:       {mode_desc}")
            if running_pid:
                print(f"  * 进程 PID:       {running_pid}")
            print(f"  * 专属公网端点:   {public_endpoint}")
            print(f"  * 安全访问密钥:   {secret_key}")
            print(f"  * 本地监听地址:   {local_endpoint}")
            print("-" * 70)
            print("  如需停止服务，请直接运行 stop.bat 或右键右下角托盘图标退出")
            print("=" * 70 + "\n")
            if sys.stdin.isatty():
                try:
                    input("按 Enter 键退出...")
                except Exception:
                    pass
            sys.exit(0)

        # 1. Ensure shared tunnel is active & start self-healing heartbeat monitor
        print(f"[*] 检查并确保共享穿透隧道在线...")
        monitor = None
        try:
            cf_path = (env_cfg.cloudflared_path if env_cfg else "") or None
            metrics_port = getattr(env_cfg, "cloudflare_metrics_port", None) if env_cfg else None
            ensure_tunnel_running(cloudflared_path=cf_path, metrics_port=metrics_port)
            if public_endpoint:
                monitor = start_tunnel_heartbeat_monitor(public_url=public_endpoint, check_interval=30.0, service_name=active_service_name)
        except Exception as e:
            print(f"[!] 隧道自检提示: {e}")

        if "--test" in sys.argv:
            print(f"[OK] {active_service_name} launcher pre-flight check passed!")
            sys.exit(0)

        # 2. Run child server runner
        print(f"[*] 正在启动 {active_service_name} (端口 {port})...\n")
        if server_runner:
            if "--no-tunnel" not in sys.argv:
                sys.argv = [sys.argv[0], "--no-tunnel"] + [arg for arg in sys.argv[1:] if arg != "--no-tunnel"]
            try:
                server_runner()
            except KeyboardInterrupt:
                pass
    except KeyboardInterrupt:
        pass
    finally:
        if "monitor" in locals() and monitor:
            try:
                monitor.stop()
            except Exception:
                pass
        sys.argv = orig_argv
        os.chdir(orig_cwd)
