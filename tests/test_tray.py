import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from PIL import Image

from mcp_server_core.tray import (
    BaseTrayApp,
    ServerProcessSupervisor,
    get_server_python_exe,
)


class TestTrayModule(unittest.TestCase):
    def test_get_server_python_exe(self):
        exe = get_server_python_exe()
        self.assertIsInstance(exe, str)
        self.assertTrue(len(exe) > 0)
        self.assertFalse(exe.lower().endswith("pythonw.exe"))

    def test_server_process_supervisor_init(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            sup = ServerProcessSupervisor(
                port=8788,
                cwd=base,
                server_cmd=[sys.executable, "-m", "app"],
                service_name="Test Service",
            )
            self.assertEqual(sup.port, 8788)
            self.assertEqual(sup.service_name, "Test Service")
            self.assertIn("127.0.0.1:8788", sup.status_text)
            self.assertFalse(sup._restarting)

            # Test stop passes candidate_ports={self.port}
            from unittest.mock import patch
            with patch("mcp_server_core.tray.stop_tunnel_if_no_mcp") as mock_stop_tunnel:
                sup.kill_stale_server_only = MagicMock()
                sup.stop()
                mock_stop_tunnel.assert_called_once_with(candidate_ports={8788})

    def test_supervisor_passes_runtime_dir_name(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            sup = ServerProcessSupervisor(
                port=8789,
                cwd=base,
                server_cmd=[sys.executable, "-m", "app"],
                service_name="Runtime Dir Service",
                runtime_dir_name=".state",
            )
            with patch("mcp_server_core.tray.kill_stale_server_process") as mock_kill, \
                 patch("mcp_server_core.tray.time.sleep"):
                sup.kill_stale_server_only()
                mock_kill.assert_called_once_with(8789, base, runtime_dir_name=".state")

    def test_base_tray_app_init_and_kwargs(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            (base / ".env").write_text("MCP_PORT=8910\nMCP_API_KEY=sec_my_key\n", encoding="utf-8")

            app = BaseTrayApp(
                service_name="Test MCP Service",
                root_dir=base,
                port=8910,
                icon_text="T",
                icon_bg_color="#e74c3c",
                server_module="my_pkg.server",
            )

            self.assertEqual(app.service_name, "Test MCP Service")
            self.assertEqual(app.port, 8910)
            self.assertEqual(app.icon_char, "T")
            self.assertEqual(app.icon_color, "#e74c3c")
            self.assertEqual(app.get_api_key(), "sec_my_key")

            # Icon generation
            img = app.create_tray_icon()
            self.assertIsInstance(img, Image.Image)
            self.assertEqual(img.size, (64, 64))

            # Menu building
            menu = app.build_menu()
            self.assertIsNotNone(menu)

            # PID recording and cleanup
            app.record_tray_pid()
            self.assertTrue(app.tray_pid_file.exists())
            self.assertEqual(int(app.tray_pid_file.read_text().strip()), os.getpid())

            app.cleanup_tray_pid()
            self.assertFalse(app.tray_pid_file.exists())

    def test_base_tray_app_custom_menu(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)

            def custom_menu_builder(app_inst):
                from pystray import MenuItem as item
                return [item("Custom Action", lambda: None)]

            app = BaseTrayApp(
                service_name="Custom Tray",
                base_dir=base,
                default_port=9011,
                custom_menu_builder=custom_menu_builder,
            )

            custom_items = app.build_custom_menu()
            self.assertEqual(len(custom_items), 1)
            menu = app.build_menu()
            self.assertIsNotNone(menu)

    def test_base_tray_app_actions(self):
        old_key = os.environ.get("MCP_API_KEY")
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                base = Path(tmp_dir)
                (base / ".env").write_text("MCP_PORT=8912\nMCP_API_KEY=sec_old_key\n", encoding="utf-8")

                app = BaseTrayApp(
                    service_name="Actions Tray",
                    base_dir=base,
                    default_port=8912,
                )

                mock_icon = MagicMock()
                app.supervisor.restart_async = MagicMock()

                # Copy URL
                app.copy_to_clipboard = MagicMock()
                app.on_copy_url(mock_icon, None)
                app.copy_to_clipboard.assert_called_with(app.get_public_url())

                # Copy Key
                app.on_copy_key(mock_icon, None)
                app.copy_to_clipboard.assert_called_with("sec_old_key")

                # Rotate Key
                app.on_rotate_key(mock_icon, None)
                new_key = app.get_api_key()
                self.assertTrue(new_key.startswith("sec_"))
                self.assertNotEqual(new_key, "sec_old_key")
                app.supervisor.restart_async.assert_called_once_with(mock_icon)

                # Restart action
                app.supervisor.restart_async.reset_mock()
                app.on_restart(mock_icon, None)
                app.supervisor.restart_async.assert_called_once_with(mock_icon)
        finally:
            if old_key is not None:
                os.environ["MCP_API_KEY"] = old_key
            else:
                os.environ.pop("MCP_API_KEY", None)

    def test_posix_message_box_and_import(self):
        with patch.object(sys, "platform", "linux"):
            from mcp_server_core.tray import BaseTrayApp
            app = BaseTrayApp(service_name="Test Linux Tray")
            self.assertEqual(app.message_box("Test Message"), 0)


if __name__ == "__main__":
    unittest.main()
