import functools
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from mcp.server.fastmcp import FastMCP
from mcp_server_core.env import DeploymentEnvConfig
from mcp_server_core.launcher import launch_service
from mcp_server_core.oauth import LocalOAuthServer
from mcp_server_core.server import (
    build_mcp_server_app,
    cleanup_pid,
    record_pid,
    run_mcp_server,
    serve_http,
    serve_stdio,
)


class TestServerAndLauncherModule(unittest.IsolatedAsyncioTestCase):
    def test_record_and_cleanup_pid(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            pid_file = record_pid(base)
            self.assertTrue(pid_file.exists())
            self.assertEqual(int(pid_file.read_text().strip()), os.getpid())

            cleanup_pid()
            self.assertFalse(pid_file.exists())

    def test_build_mcp_server_app(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            env_cfg = DeploymentEnvConfig(port=8788, require_auth=True)
            oauth_server = LocalOAuthServer(admin_password="sec_test", db_path=base / "oauth.db")
            mcp = FastMCP("AppTestServer")

            app = build_mcp_server_app(
                server=mcp,
                env_cfg=env_cfg,
                oauth_server=oauth_server,
                service_name="app_test",
            )
            self.assertIsNotNone(app)

    def test_serve_stdio(self):
        mcp = MagicMock()
        serve_stdio(mcp)
        mcp.run.assert_called_once_with(transport="stdio")

    async def test_serve_http_lifecycle(self):
        from unittest.mock import AsyncMock
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            env_cfg = DeploymentEnvConfig(
                port=8788,
                require_auth=True,
                tunnel=False,
                portal_url="https://mcp.portal.com/mcp",
                upstream_url="https://upstream.mcp.com/mcp",
            )
            mcp = FastMCP("ServeHttpTestServer")
            with patch("uvicorn.Server.serve", new_callable=AsyncMock) as mock_serve:
                await serve_http(
                    server=mcp,
                    env_cfg=env_cfg,
                    base_dir=base,
                    service_name="serve_test",
                    banner_title="Test Server Running",
                    banner_items=[("Status", "Operational")],
                )
                self.assertTrue(mock_serve.called)

    def test_run_mcp_server_stdio_mode(self):
        mcp = MagicMock()
        with tempfile.TemporaryDirectory() as tmp_dir:
            run_mcp_server(
                server=mcp,
                base_dir=Path(tmp_dir),
                service_name="test_stdio",
                cli_args=["--transport", "stdio", "--show-key"],
            )
            mcp.run.assert_called_once_with(transport="stdio")

    def test_run_mcp_server_http_mode_overrides(self):
        mcp = MagicMock()
        with tempfile.TemporaryDirectory() as tmp_dir:
            with patch("anyio.run") as mock_anyio_run:
                run_mcp_server(
                    server=mcp,
                    base_dir=Path(tmp_dir),
                    service_name="test_http",
                    banner_items_builder=lambda: [("Extra", "Info")],
                    cli_args=[
                        "--port", "9876",
                        "--host", "0.0.0.0",
                        "--key", "sec_cli_override",
                        "--no-tunnel",
                    ],
                )
                self.assertTrue(mock_anyio_run.called)
                args, _ = mock_anyio_run.call_args
                if isinstance(args[0], functools.partial):
                    env_cfg = args[0].keywords["env_cfg"]
                    banner_items = args[0].keywords["banner_items"]
                else:
                    env_cfg = args[2]
                    banner_items = args[8]
                self.assertEqual(env_cfg.port, 9876)
                self.assertEqual(env_cfg.host, "0.0.0.0")
                self.assertEqual(env_cfg.api_key, "sec_cli_override")
                self.assertFalse(env_cfg.tunnel)
                self.assertEqual(banner_items, [("Extra", "Info")])

    def test_launcher_test_flag(self):
        runner_called = False

        def dummy_runner():
            nonlocal runner_called
            runner_called = True

        with tempfile.TemporaryDirectory() as tmp_dir:
            old_argv = sys.argv
            try:
                sys.argv = ["test_prog", "--test"]
                with (
                    patch("mcp_server_core.launcher.ensure_tunnel_running") as mock_tunnel,
                    patch("mcp_server_core.launcher.start_tunnel_heartbeat_monitor") as mock_monitor,
                    self.assertRaises(SystemExit) as ctx,
                ):
                    launch_service(
                        service_name="LauncherTest",
                        server_runner=dummy_runner,
                        default_port=59333,
                        root_dir=Path(tmp_dir),
                    )
                self.assertEqual(ctx.exception.code, 0)
                self.assertFalse(runner_called)
                mock_tunnel.assert_called_once()
            finally:
                sys.argv = old_argv

    def test_launcher_stop_flag(self):
        runner_called = False

        def dummy_runner():
            nonlocal runner_called
            runner_called = True

        with tempfile.TemporaryDirectory() as tmp_dir:
            old_argv = sys.argv
            try:
                sys.argv = ["test_prog", "--stop"]
                with self.assertRaises(SystemExit) as ctx:
                    launch_service(
                        service_name="LauncherStopTest",
                        server_runner=dummy_runner,
                        default_port=59334,
                        root_dir=Path(tmp_dir),
                    )
                self.assertEqual(ctx.exception.code, 0)
                self.assertFalse(runner_called)
            finally:
                sys.argv = old_argv


    def test_launcher_passes_runtime_dir_to_process_helpers(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            (base / ".env").write_text(
                "MCP_PORT=59445\n"
                "MCP_API_KEY=sec_test\n"
                "MCP_REQUIRE_AUTH=true\n"
                "MCP_RUNTIME_DIR=.state\n",
                encoding="utf-8",
            )
            old_argv = sys.argv
            try:
                sys.argv = ["test_prog", "--stop"]
                with patch(
                    "mcp_server_core.launcher.stop_mcp_service",
                    return_value={"killed_pids": []},
                ) as mock_stop:
                    with self.assertRaises(SystemExit):
                        launch_service(
                            service_name="RuntimeDirStop",
                            server_runner=lambda: None,
                            default_port=59445,
                            root_dir=base,
                        )
                    mock_stop.assert_called_once_with(59445, base, runtime_dir_name=".state")

                sys.argv = ["test_prog", "--test"]
                with patch(
                    "mcp_server_core.launcher.check_service_status",
                    return_value=(False, "", None),
                ) as mock_check, patch(
                    "mcp_server_core.launcher.ensure_tunnel_running",
                    return_value=False,
                ), patch(
                    "mcp_server_core.launcher.start_tunnel_heartbeat_monitor"
                ):
                    with self.assertRaises(SystemExit):
                        launch_service(
                            service_name="RuntimeDirCheck",
                            server_runner=lambda: None,
                            default_port=59445,
                            root_dir=base,
                        )
                    args, kwargs = mock_check.call_args
                    self.assertEqual(args[0], 59445)
                    self.assertEqual(kwargs.get("runtime_dir_name"), ".state")
            finally:
                sys.argv = old_argv

    def test_launcher_running_already_detection(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            with patch("mcp_server_core.launcher.check_service_status", return_value=(True, "Tray App", 12345)):
                with self.assertRaises(SystemExit) as ctx:
                    launch_service(
                        service_name="AlreadyRunningApp",
                        server_runner=lambda: None,
                        default_port=59444,
                        root_dir=base,
                    )
                self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
