import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from mcp_server_core.tunnel import (
    CloudflareTunnel,
    TunnelHeartbeatMonitor,
    check_tunnel_health,
    find_cloudflared,
    get_cloudflare_ingress_ports,
    get_public_tunnel_url,
    get_tunnel_token,
    is_cloudflared_available,
    is_port_listening,
    is_tunnel_running,
    restart_tunnel,
    start_tunnel_heartbeat_monitor,
    stop_tunnel_if_no_mcp,
)


class TestTunnelModule(unittest.TestCase):
    def test_find_cloudflared(self):
        # 1. Custom path
        with tempfile.TemporaryDirectory() as tmp_dir:
            fake_bin = Path(tmp_dir) / ("cloudflared.exe" if os.name == "nt" else "cloudflared")
            fake_bin.touch()
            found = find_cloudflared(fake_bin)
            self.assertEqual(found, fake_bin.resolve())

            # 2. Directory containing binary
            found_dir = find_cloudflared(Path(tmp_dir))
            self.assertEqual(found_dir, fake_bin.resolve())

        # 3. Environment variable
        with tempfile.TemporaryDirectory() as tmp_dir:
            fake_bin = Path(tmp_dir) / ("cloudflared.exe" if os.name == "nt" else "cloudflared")
            fake_bin.touch()
            old_env = os.environ.get("CLOUDFLARED_PATH")
            try:
                os.environ["CLOUDFLARED_PATH"] = str(fake_bin)
                found = find_cloudflared()
                self.assertEqual(found, fake_bin.resolve())
            finally:
                if old_env is not None:
                    os.environ["CLOUDFLARED_PATH"] = old_env
                else:
                    os.environ.pop("CLOUDFLARED_PATH", None)

        # 4. Fallback to package bundled binary
        bundled = find_cloudflared()
        self.assertTrue(bundled.exists())

        # 5. Not found when all fallbacks fail
        from unittest.mock import patch
        with patch("shutil.which", return_value=None), \
             patch("pathlib.Path.exists", return_value=False):
            with self.assertRaises(FileNotFoundError):
                find_cloudflared()

    def test_is_cloudflared_available(self):
        # Should return a boolean
        self.assertIsInstance(is_cloudflared_available(), bool)

    def test_is_port_listening(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            port = s.getsockname()[1]
            self.assertTrue(is_port_listening(port))

        self.assertFalse(is_port_listening(port))

    def test_get_tunnel_token(self):
        old_val = os.environ.get("CLOUDFLARE_TUNNEL_TOKEN")
        try:
            os.environ["CLOUDFLARE_TUNNEL_TOKEN"] = "token_abc_123"
            self.assertEqual(get_tunnel_token(), "token_abc_123")
        finally:
            if old_val is not None:
                os.environ["CLOUDFLARE_TUNNEL_TOKEN"] = old_val
            else:
                os.environ.pop("CLOUDFLARE_TUNNEL_TOKEN", None)

    def test_get_tunnel_token_from_global_env(self):
        with tempfile.TemporaryDirectory() as tmp_global, tempfile.TemporaryDirectory() as tmp_proj:
            global_env = Path(tmp_global) / ".env"
            global_env.write_text("CLOUDFLARE_TUNNEL_TOKEN=global_tok_555\n", encoding="utf-8")

            # Clean os.environ
            old_val = os.environ.pop("CLOUDFLARE_TUNNEL_TOKEN", None)
            old_mcp = os.environ.pop("MCP_TUNNEL_TOKEN", None)
            old_global_env = os.environ.get("MCP_GLOBAL_ENV")
            try:
                os.environ["MCP_GLOBAL_ENV"] = str(global_env)

                # 1. Project .env has empty placeholder -> fallback to global
                proj_env = Path(tmp_proj) / ".env"
                proj_env.write_text("CLOUDFLARE_TUNNEL_TOKEN=\n", encoding="utf-8")
                token = get_tunnel_token(base_dir=tmp_proj)
                self.assertEqual(token, "global_tok_555")

                # 2. Project .env has explicit token -> project token takes precedence
                proj_env.write_text("CLOUDFLARE_TUNNEL_TOKEN=proj_tok_777\n", encoding="utf-8")
                token2 = get_tunnel_token(base_dir=tmp_proj)
                self.assertEqual(token2, "proj_tok_777")
            finally:
                if old_val is not None:
                    os.environ["CLOUDFLARE_TUNNEL_TOKEN"] = old_val
                if old_mcp is not None:
                    os.environ["MCP_TUNNEL_TOKEN"] = old_mcp
                if old_global_env is not None:
                    os.environ["MCP_GLOBAL_ENV"] = old_global_env
                else:
                    os.environ.pop("MCP_GLOBAL_ENV", None)

    def test_find_cloudflared_from_global_env(self):
        with tempfile.TemporaryDirectory() as tmp_global, tempfile.TemporaryDirectory() as tmp_bin_dir:
            fake_bin = Path(tmp_bin_dir) / ("cloudflared.exe" if os.name == "nt" else "cloudflared")
            fake_bin.touch()

            global_env = Path(tmp_global) / ".env"
            global_env.write_text(f"CLOUDFLARED_PATH={fake_bin}\n", encoding="utf-8")

            old_env_path = os.environ.pop("CLOUDFLARED_PATH", None)
            old_env_bin = os.environ.pop("CLOUDFLARED_BIN", None)
            old_global_env = os.environ.get("MCP_GLOBAL_ENV")
            try:
                os.environ["MCP_GLOBAL_ENV"] = str(global_env)
                found = find_cloudflared()
                self.assertEqual(found, fake_bin.resolve())
            finally:
                if old_env_path is not None:
                    os.environ["CLOUDFLARED_PATH"] = old_env_path
                if old_env_bin is not None:
                    os.environ["CLOUDFLARED_BIN"] = old_env_bin
                if old_global_env is not None:
                    os.environ["MCP_GLOBAL_ENV"] = old_global_env
                else:
                    os.environ.pop("MCP_GLOBAL_ENV", None)

    def test_get_cloudflare_ingress_ports_fallback(self):
        import urllib.error
        from unittest.mock import patch

        # When cloudflared metrics is not running (raises error), fallback to DEFAULT_FALLBACK_PORTS or custom fallback
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            ports = get_cloudflare_ingress_ports()
            self.assertIsInstance(ports, set)
            self.assertEqual(ports, {8788})

            # Custom dynamic fallback
            custom_ports = get_cloudflare_ingress_ports(fallback_ports={9005, 9006})
            self.assertEqual(custom_ports, {9005, 9006})

    def test_get_cloudflare_ingress_ports_mocked(self):
        import io
        import json
        from unittest.mock import patch

        mock_config = {
            "config": {
                "ingress": [
                    {"service": "http://127.0.0.1:8788"},
                    {"service": "https://localhost:9100"},
                    {"service": "tcp://127.0.0.1:2222"},
                    {"service": "http_status:404"},
                ]
            }
        }
        mock_resp = io.BytesIO(json.dumps(mock_config).encode("utf-8"))

        with patch("urllib.request.urlopen", return_value=mock_resp):
            ports = get_cloudflare_ingress_ports()
            self.assertEqual(ports, {8788, 9100, 2222})

    def test_check_tunnel_health_mocked(self):
        from unittest.mock import MagicMock, patch

        # 200 OK
        resp_200 = MagicMock()
        resp_200.__enter__.return_value = MagicMock(status=200)
        with patch("urllib.request.urlopen", return_value=resp_200):
            self.assertTrue(check_tunnel_health("https://example.com"))

        # HTTP 302 Found (Redirection is in 200..399 range)
        import urllib.error
        err_302 = urllib.error.HTTPError("https://example.com/health", 302, "Found", {}, None)
        with patch("urllib.request.urlopen", side_effect=err_302):
            self.assertTrue(check_tunnel_health("https://example.com"))

        # HTTP 502 Bad Gateway (Tunnel down)
        err_502 = urllib.error.HTTPError("https://example.com/health", 502, "Bad Gateway", {}, None)
        with patch("urllib.request.urlopen", side_effect=err_502):
            self.assertFalse(check_tunnel_health("https://example.com"))

        # Verify dynamic User-Agent header
        captured_req = None
        def mock_open(req, timeout=5.0):
            nonlocal captured_req
            captured_req = req
            m = MagicMock()
            m.__enter__.return_value = MagicMock(status=200)
            return m

        with patch("urllib.request.urlopen", side_effect=mock_open):
            check_tunnel_health("https://example.com", service_name="MyService")
            self.assertIsNotNone(captured_req)
            self.assertEqual(captured_req.headers.get("User-agent"), "MyService-Tunnel-Heartbeat/1.0")

    def test_get_public_tunnel_url(self):
        old_val = os.environ.get("PUBLIC_BASE_URL")
        try:
            os.environ["PUBLIC_BASE_URL"] = "https://custom.tunnel.example.com"
            self.assertEqual(get_public_tunnel_url(), "https://custom.tunnel.example.com")
        finally:
            if old_val is not None:
                os.environ["PUBLIC_BASE_URL"] = old_val
            else:
                os.environ.pop("PUBLIC_BASE_URL", None)

    def test_check_tunnel_health_empty(self):
        # Empty or unreachable URL returns False
        self.assertFalse(check_tunnel_health("http://127.0.0.1:59999", timeout=0.2))

    def test_cloudflare_tunnel_class(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            fake_bin = Path(tmp_dir) / ("cloudflared.exe" if os.name == "nt" else "cloudflared")
            fake_bin.touch()

            tunnel = CloudflareTunnel(
                local_port=8999,
                local_host="127.0.0.1",
                cloudflared_path=fake_bin,
                tunnel_token="test_token",
                public_url="https://test.trycloudflare.com",
            )
            self.assertEqual(tunnel.local_port, 8999)
            self.assertEqual(tunnel.local_host, "127.0.0.1")
            self.assertEqual(tunnel.tunnel_token, "test_token")
            self.assertEqual(tunnel.public_url, "https://test.trycloudflare.com")

            # Safely stop even when not running
            tunnel.stop()

    def test_tunnel_heartbeat_monitor(self):
        healed = False

        def on_heal_callback():
            nonlocal healed
            healed = True

        monitor = TunnelHeartbeatMonitor(
            public_url="http://127.0.0.1:59998",
            check_interval=5.0,
            max_consecutive_failures=2,
            on_heal=on_heal_callback,
        )
        self.assertEqual(monitor.consecutive_failures, 0)

        # Synchronous probe against unreachable port
        res = monitor.probe_now(timeout=0.2)
        self.assertFalse(res)
        self.assertEqual(monitor.consecutive_failures, 1)

        # Test start and stop
        monitor.start()
        self.assertIsNotNone(monitor._thread)
        monitor.stop()
        self.assertIsNone(monitor._thread)

    def test_start_tunnel_heartbeat_monitor_factory(self):
        monitor = start_tunnel_heartbeat_monitor(public_url="https://example.com", check_interval=10.0)
        self.assertIsInstance(monitor, TunnelHeartbeatMonitor)
        self.assertIsNotNone(monitor._thread)
        self.assertTrue(monitor._thread.is_alive())
        monitor.stop()
        self.assertIsNone(monitor._thread)

    @patch("subprocess.run")
    def test_is_tunnel_running_windows(self, mock_run):
        with patch.object(sys, "platform", "win32"):
            mock_run.return_value = MagicMock(returncode=0, stdout="cloudflared.exe 1234")
            self.assertTrue(is_tunnel_running())
            mock_run.assert_called_with(
                ["tasklist", "/fi", "imagename eq cloudflared.exe"],
                capture_output=True,
                text=True,
                errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )

            mock_run.return_value = MagicMock(returncode=0, stdout="INFO: No tasks running.")
            self.assertFalse(is_tunnel_running())

    @patch("subprocess.run")
    def test_is_tunnel_running_posix(self, mock_run):
        with patch.object(sys, "platform", "linux"):
            mock_run.return_value = MagicMock(returncode=0, stdout="1234\n")
            self.assertTrue(is_tunnel_running())
            mock_run.assert_called_with(
                ["pgrep", "-x", "cloudflared"],
                capture_output=True,
                text=True,
            )

            mock_run.return_value = MagicMock(returncode=1, stdout="")
            self.assertFalse(is_tunnel_running())

    @patch("mcp_server_core.tunnel.is_port_listening", return_value=False)
    @patch("mcp_server_core.tunnel.get_cloudflare_ingress_ports", return_value={8788})
    @patch("subprocess.run")
    def test_stop_tunnel_if_no_mcp_invocations(self, mock_run, mock_ingress, mock_listening):
        with patch.object(sys, "platform", "win32"):
            res = stop_tunnel_if_no_mcp()
            self.assertTrue(res)
            mock_run.assert_called_with(
                ["taskkill", "/f", "/im", "cloudflared.exe"],
                capture_output=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )

        mock_run.reset_mock()
        with patch.object(sys, "platform", "linux"):
            res = stop_tunnel_if_no_mcp()
            self.assertTrue(res)
            mock_run.assert_called_with(
                ["pkill", "-x", "cloudflared"],
                capture_output=True,
            )

    @patch("mcp_server_core.tunnel.ensure_tunnel_running", return_value=True)
    @patch("time.sleep")
    @patch("subprocess.run")
    def test_restart_tunnel_invocations(self, mock_run, mock_sleep, mock_ensure):
        with patch.object(sys, "platform", "win32"):
            res = restart_tunnel()
            self.assertTrue(res)
            mock_run.assert_called_with(
                ["taskkill", "/f", "/im", "cloudflared.exe"],
                capture_output=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            mock_ensure.assert_called_once()

        mock_run.reset_mock()
        mock_ensure.reset_mock()
        with patch.object(sys, "platform", "linux"):
            res = restart_tunnel()
            self.assertTrue(res)
            mock_run.assert_called_with(
                ["pkill", "-x", "cloudflared"],
                capture_output=True,
            )
            mock_ensure.assert_called_once()

    def test_is_cloudflared_available_custom_path_and_metrics_port(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            fake_bin = Path(tmp_dir) / ("cloudflared.exe" if os.name == "nt" else "cloudflared")
            fake_bin.touch()
            self.assertTrue(is_cloudflared_available(fake_bin))
            self.assertEqual(find_cloudflared(fake_bin), fake_bin.resolve())

            from mcp_server_core.tunnel import ensure_tunnel_running
            with patch("mcp_server_core.tunnel.is_tunnel_running", return_value=False):
                with patch("subprocess.Popen") as mock_popen:
                    with patch("time.sleep"):
                        ensure_tunnel_running(token="fake_tok", cloudflared_path=fake_bin, metrics_port=29999)
                        self.assertTrue(mock_popen.called)
                        call_cmd = mock_popen.call_args[0][0]
                        self.assertIn("--metrics", call_cmd)
                        self.assertIn("127.0.0.1:29999", call_cmd)


if __name__ == "__main__":
    unittest.main()
