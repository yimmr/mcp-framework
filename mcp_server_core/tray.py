"""Reusable Windows System Tray Application Base for MCP Services."""
from __future__ import annotations

import atexit
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any, Callable

from .console import configure_console_encoding

configure_console_encoding()

if sys.platform == "win32":
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass

try:
    from PIL import Image, ImageDraw, ImageFont
    import pystray
    from pystray import MenuItem as item
except ImportError as err:
    pystray = None
    item = None

if sys.platform == "win32":
    import win32api
    import win32clipboard
    import win32con
    import win32event
    import win32job
    import winerror
else:
    win32api = win32clipboard = win32con = win32event = win32job = winerror = None

from .env import DeploymentEnvConfig, get_runtime_dir, update_env_variable
from .process import is_port_in_use, kill_stale_server_process
from .tunnel import ensure_tunnel_running, stop_tunnel_if_no_mcp


def get_server_python_exe() -> str:
    """Ensure child server runs with python.exe (with CREATE_NO_WINDOW) rather than pythonw.exe."""
    py_exe = sys.executable
    if py_exe.lower().endswith("pythonw.exe"):
        cand = py_exe[:-5] + ".exe"
        if os.path.exists(cand):
            return cand
    return py_exe


class ServerProcessSupervisor:
    """Supervises child MCP server subprocess lifecycle bound to a Windows Job Object."""

    def __init__(
        self,
        port: int,
        cwd: Path,
        server_cmd: list[str],
        service_name: str,
        runtime_dir_name: str | None = None,
    ):
        self.port = port
        self.cwd = cwd
        self.server_cmd = server_cmd
        self.service_name = service_name
        self.runtime_dir = get_runtime_dir(cwd, runtime_dir_name=runtime_dir_name)
        self.runtime_dir_name = runtime_dir_name or self.runtime_dir.name
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.proc: subprocess.Popen | None = None
        self.job = None
        self.status_text = f"● 【运行中】127.0.0.1:{self.port}"
        self._restarting = False
        self._init_job_object()

    def _init_job_object(self) -> None:
        if sys.platform != "win32":
            return
        try:
            job = win32job.CreateJobObject(None, "")
            info = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
            info["BasicLimitInformation"]["LimitFlags"] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, info)
            self.job = job
        except Exception:
            self.job = None

    def kill_stale_server_only(self) -> None:
        kill_stale_server_process(self.port, self.cwd, runtime_dir_name=self.runtime_dir_name)
        time.sleep(0.3)

    def _spawn_process(self) -> None:
        creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}

        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        # Only pass explicit user-set MCP_LOG_DIR, never forcibly override child's config.yaml
        log_dir_str = os.getenv("MCP_LOG_DIR", "").strip()
        if log_dir_str:
            log_dir = Path(log_dir_str)
            if not log_dir.is_absolute():
                log_dir = (self.cwd / log_dir).resolve()
            env["MCP_LOG_DIR"] = str(log_dir)
        else:
            log_dir = (self.runtime_dir / "logs").resolve()
        log_dir.mkdir(parents=True, exist_ok=True)

        out_file = None
        err_file = None
        try:
            out_file = open(log_dir / "boot.out.log", "a", encoding="utf-8")
        except Exception:
            pass
        try:
            err_file = open(log_dir / "boot.err.log", "a", encoding="utf-8")
        except Exception:
            pass

        try:
            self.proc = subprocess.Popen(
                self.server_cmd,
                cwd=str(self.cwd),
                creationflags=creationflags,
                env=env,
                stdout=out_file or subprocess.DEVNULL,
                stderr=err_file or subprocess.DEVNULL,
            )
        finally:
            if out_file:
                try:
                    out_file.close()
                except Exception:
                    pass
            if err_file:
                try:
                    err_file.close()
                except Exception:
                    pass

        if self.job and self.proc and getattr(self.proc, "_handle", None):
            try:
                win32job.AssignProcessToJobObject(self.job, self.proc._handle)
            except Exception:
                pass

    def start(self) -> None:
        self.kill_stale_server_only()
        ensure_tunnel_running()
        self._spawn_process()

    def stop(self) -> None:
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=2)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            self.proc = None
        self.kill_stale_server_only()
        stop_tunnel_if_no_mcp(candidate_ports={self.port})

    def restart_async(self, icon: Any | None = None) -> None:
        if self._restarting:
            return
        threading.Thread(target=self._do_restart, args=(icon,), daemon=True).start()

    def _do_restart(self, icon: Any | None = None) -> None:
        self._restarting = True
        self.status_text = f"● 【重启中...】127.0.0.1:{self.port}"
        if icon:
            try:
                icon.update_menu()
                icon.notify("正在重启 MCP 服务，请稍候...", self.service_name)
            except Exception:
                pass

        try:
            if self.proc:
                try:
                    self.proc.terminate()
                    self.proc.wait(timeout=2)
                except Exception:
                    try:
                        self.proc.kill()
                    except Exception:
                        pass
                self.proc = None

            self.kill_stale_server_only()
            ensure_tunnel_running()
            self._spawn_process()

            healthy = False
            for _ in range(20):
                time.sleep(0.5)
                try:
                    req = urllib.request.Request(f"http://127.0.0.1:{self.port}/health")
                    with urllib.request.urlopen(req, timeout=1) as resp:
                        if resp.status == 200:
                            healthy = True
                            break
                except Exception:
                    pass

            if healthy:
                self.status_text = f"● 【运行中】127.0.0.1:{self.port}"
                if icon:
                    try:
                        icon.update_menu()
                        icon.notify(f"服务已重启完成并就绪 (端口 {self.port})", self.service_name)
                    except Exception:
                        pass
            else:
                self.status_text = f"● 【异常】端口 {self.port} 未响应"
                if icon:
                    try:
                        icon.update_menu()
                        icon.notify("警告：服务重启超时，健康检查未通过！", self.service_name)
                    except Exception:
                        pass
        finally:
            self._restarting = False


class BaseTrayApp:
    """Base class for Windows System Tray applications powering local MCP servers."""

    def __init__(
        self,
        service_name: str | None = None,
        base_dir: Path | str | None = None,
        default_port: int = 8788,
        icon_char: str = "M",
        icon_color: str = "#00b894",
        server_module: str | None = "app",
        server_cmd: list[str] | None = None,
        custom_menu_builder: Callable[[BaseTrayApp], list[Any]] | None = None,
        **kwargs: Any,
    ):
        if pystray is None:
            raise RuntimeError(
                "pystray and pillow are required for BaseTrayApp. Please install them: pip install pystray pillow pywin32"
            )

        # Handle alias kwargs gracefully
        base_dir = kwargs.get("root_dir", base_dir)
        default_port = kwargs.get("port", default_port)
        icon_char = kwargs.get("icon_text", icon_char)
        icon_color = kwargs.get("icon_bg_color", icon_color)

        self.base_dir = Path(base_dir).resolve() if base_dir else Path.cwd().resolve()
        cfg = self.get_current_env()
        self.service_name = service_name or (cfg.display_title if cfg else "MCP Service")
        rdir_name = getattr(cfg, "runtime_dir", None) if cfg else None
        self.runtime_dir = get_runtime_dir(self.base_dir, runtime_dir_name=rdir_name)
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.default_port = default_port
        self.icon_char = icon_char
        self.icon_color = icon_color
        self.custom_menu_builder = custom_menu_builder

        self.port = self.get_port()
        self.mutex_name = f"Local\\{self.service_name.replace(' ', '_')}_{self.port}"
        self.tray_pid_file = self.runtime_dir / ".tray.pid"

        if server_cmd is not None:
            self.server_cmd = server_cmd
        else:
            py_exe = get_server_python_exe()
            mod = server_module or "app"
            self.server_cmd = [py_exe, "-m", mod, "--no-tunnel"]

        self.supervisor = ServerProcessSupervisor(
            port=self.port,
            cwd=self.base_dir,
            server_cmd=self.server_cmd,
            service_name=self.service_name,
            runtime_dir_name=rdir_name,
        )
        self.icon: pystray.Icon | None = None

    def get_current_env(self) -> DeploymentEnvConfig | None:
        try:
            return DeploymentEnvConfig.load(self.base_dir)
        except Exception:
            return None

    def get_port(self) -> int:
        cfg = self.get_current_env()
        if cfg and cfg.port:
            return cfg.port
        return self.default_port

    def get_api_key(self) -> str:
        cfg = self.get_current_env()
        if cfg and cfg.api_key:
            return cfg.api_key
        return os.getenv("MCP_API_KEY", "")

    def get_public_url(self) -> str:
        cfg = self.get_current_env()
        if cfg and cfg.upstream_url:
            return cfg.upstream_url
        return os.getenv("TUNNEL_PUBLIC_URL", f"http://127.0.0.1:{self.port}/mcp")

    def record_tray_pid(self) -> None:
        try:
            self.runtime_dir.mkdir(parents=True, exist_ok=True)
            self.tray_pid_file.write_text(str(os.getpid()), encoding="utf-8")
        except Exception:
            pass

    def cleanup_tray_pid(self) -> None:
        for t_file in [self.tray_pid_file, self.base_dir / ".tray.pid"]:
            try:
                if t_file.exists():
                    t_file.unlink()
            except Exception:
                pass

    def ensure_single_instance(self) -> Any:
        if sys.platform != "win32":
            return None
        mutex = win32event.CreateMutex(None, False, self.mutex_name)
        if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
            try:
                win32api.MessageBox(
                    0,
                    f"【提示】{self.service_name} 已在系统托盘运行中！\n\n请在任务栏右下角通知区域查看图标。\n如需停止，可右键托盘图标退出或运行 stop.bat。",
                    self.service_name,
                    win32con.MB_ICONINFORMATION | win32con.MB_OK | win32con.MB_SYSTEMMODAL,
                )
            except Exception:
                pass
            sys.exit(0)
        return mutex

    def copy_to_clipboard(self, text: str) -> None:
        if sys.platform != "win32":
            return
        try:
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardText(text, win32con.CF_UNICODETEXT)
            win32clipboard.CloseClipboard()
        except Exception as e:
            print("Clipboard error:", e)

    def message_box(
        self,
        text: str,
        title: str | None = None,
        flags: int | None = None,
    ) -> int:
        if sys.platform != "win32" or not win32api or not win32con:
            return 0
        if flags is None:
            flags = win32con.MB_ICONINFORMATION | win32con.MB_OK | win32con.MB_SYSTEMMODAL
        return win32api.MessageBox(0, text, title or self.service_name, flags)

    def choose_folder(self, title: str = "选择文件夹") -> str | None:
        """Open native high-DPI directory chooser dialog with Tkinter or PowerShell fallback."""
        try:
            import tkinter as tk
            from tkinter import filedialog
            root = tk.Tk()
            root.withdraw()
            root.attributes("-topmost", True)

            ico_path = self.runtime_dir / "app.ico"
            if not ico_path.exists():
                try:
                    self.create_tray_icon().save(ico_path, format="ICO")
                except Exception:
                    pass
            if ico_path.exists():
                try:
                    root.iconbitmap(str(ico_path))
                except Exception:
                    pass

            folder = filedialog.askdirectory(title=title, parent=root)
            root.destroy()
            if folder:
                return folder
        except Exception:
            pass

        try:
            ps_cmd = (
                'Add-Type -AssemblyName System.Windows.Forms; '
                '$fb = New-Object System.Windows.Forms.FolderBrowserDialog; '
                f'$fb.Description = "{title}"; '
                '$fb.ShowNewFolderButton = $true; '
                'if ($fb.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { '
                '    Write-Output $fb.SelectedPath '
                '}'
            )
            creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                creationflags=creationflags,
            )
            out = res.stdout.strip()
            return out if out else None
        except Exception:
            return None

    def create_tray_icon(self) -> Image.Image:
        """Create round dynamic tray icon with customizable letter and background color."""
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.ellipse((4, 4, 60, 60), fill=self.icon_color)
        try:
            font = ImageFont.truetype("arial.ttf", 36)
            draw.text((18, 12), self.icon_char, fill="white", font=font)
        except Exception:
            draw.text((22, 16), self.icon_char, fill="white")
        return img

    def build_custom_menu(self) -> list[Any]:
        """Override this method or pass custom_menu_builder to inject business-specific menu items."""
        if self.custom_menu_builder:
            return self.custom_menu_builder(self)
        return []

    # Standard actions
    def on_copy_url(self, icon: Any, _menu_item: Any) -> None:
        url = self.get_public_url()
        self.copy_to_clipboard(url)
        try:
            icon.notify("已复制 MCP 服务器网址:\n" + url, self.service_name)
        except Exception:
            pass

    def on_copy_key(self, icon: Any, _menu_item: Any) -> None:
        key = self.get_api_key()
        self.copy_to_clipboard(key)
        try:
            icon.notify("已复制访问密匙:\n" + key, self.service_name)
        except Exception:
            pass

    def on_rotate_key(self, icon: Any, _menu_item: Any) -> None:
        new_key = f"sec_{secrets.token_urlsafe(16)}"
        env_file = self.base_dir / ".env"
        update_env_variable("MCP_API_KEY", new_key, env_file)
        os.environ["MCP_API_KEY"] = new_key
        self.copy_to_clipboard(new_key)
        try:
            icon.notify(
                f"已生成新访问密匙并复制到剪贴板！\n{new_key}\n正在平滑重启服务以生效...",
                self.service_name,
            )
        except Exception:
            pass
        self.supervisor.restart_async(icon)

    def on_open_health(self, icon: Any, _menu_item: Any) -> None:
        webbrowser.open(f"http://127.0.0.1:{self.port}/health")

    def on_restart(self, icon: Any, _menu_item: Any) -> None:
        self.supervisor.restart_async(icon)

    def on_exit(self, icon: Any, _menu_item: Any) -> None:
        def do_exit():
            try:
                icon.title = f"{self.service_name} (正在退出...)"
                icon.notify(f"{self.service_name} 正在停止服务，请稍候...", self.service_name)
            except Exception:
                pass
            try:
                self.supervisor.stop()
            except Exception:
                pass
            self.cleanup_tray_pid()
            try:
                icon.visible = False
                icon.stop()
            except Exception:
                pass
            os._exit(0)

        threading.Thread(target=do_exit, daemon=True).start()

    def build_menu(self) -> pystray.Menu:
        items = []

        # 1. Status header
        items.append(item(lambda _: self.supervisor.status_text, None, enabled=False))
        items.append(pystray.Menu.SEPARATOR)

        # 2. Custom business menu items slot
        custom_items = self.build_custom_menu()
        if custom_items:
            items.extend(custom_items)
            items.append(pystray.Menu.SEPARATOR)

        # 3. Standard platform tools
        items.append(item("复制 MCP 服务器网址", self.on_copy_url))
        items.append(item("复制访问密匙", self.on_copy_key))
        items.append(item("重设访问密匙", self.on_rotate_key))
        items.append(item("健康检查", self.on_open_health))
        items.append(pystray.Menu.SEPARATOR)

        # 4. Lifecycle controls
        items.append(item("重启", self.on_restart))
        items.append(item("退出", self.on_exit))

        return pystray.Menu(*items)

    def run(self) -> None:
        mutex = self.ensure_single_instance()

        if is_port_in_use(self.port):
            try:
                self.message_box(
                    f"{self.service_name} 已在运行中 (端口 {self.port} 已被占用)。\n\n如需切换为无黑框托盘常驻模式，请先运行 stop.bat 停止现有服务后再启动。",
                    flags=win32con.MB_ICONINFORMATION | win32con.MB_OK | win32con.MB_SYSTEMMODAL,
                )
            except Exception:
                pass
            sys.exit(0)

        self.record_tray_pid()
        atexit.register(self.cleanup_tray_pid)

        self.supervisor.start()

        self.icon = pystray.Icon(
            name=f"{self.service_name.lower().replace(' ', '_')}_tray",
            icon=self.create_tray_icon(),
            title=f"{self.service_name} (端口 {self.port})",
            menu=self.build_menu(),
        )

        try:
            self.icon.run()
        except Exception as e:
            import traceback
            try:
                logs_dir = self.runtime_dir / "logs"
                logs_dir.mkdir(parents=True, exist_ok=True)
                (logs_dir / "tray_error.log").write_text(
                    f"Exception: {e}\n{traceback.format_exc()}", encoding="utf-8"
                )
            except Exception:
                pass
        finally:
            try:
                self.supervisor.stop()
            except Exception:
                pass
            self.cleanup_tray_pid()
            os._exit(0)
