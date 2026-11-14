import os
import socket
import tempfile
import unittest
from pathlib import Path

from mcp_server_core.process import (
    check_service_status,
    find_pid_by_port,
    is_mcp_or_related_process,
    is_pid_alive,
    is_port_in_use,
    kill_pid,
    kill_stale_server_process,
    read_pids_from_files,
    stop_mcp_service,
)


class TestProcessModule(unittest.TestCase):
    def test_is_pid_alive(self):
        # Current process must be alive
        self.assertTrue(is_pid_alive(os.getpid()))

        # Invalid PIDs
        self.assertFalse(is_pid_alive(0))
        self.assertFalse(is_pid_alive(-1))
        self.assertFalse(is_pid_alive(9999999))

    def test_kill_pid_guards(self):
        # Guard against self termination or invalid PIDs
        self.assertFalse(kill_pid(os.getpid()))
        self.assertFalse(kill_pid(0))
        self.assertFalse(kill_pid(-5))

    def test_is_port_in_use(self):
        # Bind temporary server socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            port = s.getsockname()[1]

            self.assertTrue(is_port_in_use(port))

        # Once closed, port should not be in use
        self.assertFalse(is_port_in_use(port))

    def test_find_pid_by_port_unused(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        # An unbound port shouldn't return a listening PID
        pid = find_pid_by_port(port)
        self.assertIsNone(pid)

    def test_find_pid_by_port_exact_port_isolation(self):
        # Simulate netstat output where a longer port substring appears first
        mock_output = (
            "  TCP    0.0.0.0:18788          0.0.0.0:0              LISTENING       9999\n"
            "  TCP    0.0.0.0:8788           0.0.0.0:0              LISTENING       1234\n"
        )
        from unittest.mock import patch
        with patch("subprocess.check_output", return_value=mock_output):
            # Port 8788 must match 1234, NOT 9999!
            pid = find_pid_by_port(8788)
            self.assertEqual(pid, 1234)

            # Port 18788 matches 9999
            pid_18788 = find_pid_by_port(18788)
            self.assertEqual(pid_18788, 9999)

            # Port 788 does not match either
            pid_788 = find_pid_by_port(788)
            self.assertIsNone(pid_788)

    def test_find_pid_by_port_posix_fallback(self):
        from unittest.mock import patch
        import sys

        # 1. Test lsof output
        with patch.object(sys, "platform", "linux"):
            with patch("subprocess.check_output", return_value="4321\n"):
                pid = find_pid_by_port(8788)
                self.assertEqual(pid, 4321)

        # 2. Test ss -tlpn fallback when lsof fails
        def fake_check_output(cmd, **kwargs):
            if cmd[0] == "lsof":
                raise FileNotFoundError("lsof not found")
            if cmd[0] == "ss":
                return "LISTEN 0 128 0.0.0.0:8788 0.0.0.0:* users:((\"python\",pid=5678,fd=3))\n"
            raise RuntimeError("unexpected command")

        with patch.object(sys, "platform", "linux"):
            with patch("subprocess.check_output", side_effect=fake_check_output):
                pid = find_pid_by_port(8788)
                self.assertEqual(pid, 5678)

    def test_check_service_status_inactive(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            active, desc, pid = check_service_status(port=59123, root_dir=base)
            self.assertFalse(active)
            self.assertEqual(desc, "")
            self.assertIsNone(pid)

    def test_check_service_status_with_pid_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            runtime_dir = base / ".runtime"
            runtime_dir.mkdir(parents=True, exist_ok=True)

            server_pid_file = runtime_dir / ".server.pid"
            server_pid_file.write_text(str(os.getpid()), encoding="utf-8")

            active, desc, pid = check_service_status(port=59124, root_dir=base)
            self.assertTrue(active)
            self.assertIn("核心服务进程", desc)
            self.assertEqual(pid, os.getpid())

    def test_check_service_status_with_mutex(self):
        import sys
        if sys.platform != "win32":
            return
        import win32api
        import win32event
        mutex_name = "Local\\Test_Mcp_Core_Unique_Mutex"
        h_mutex = win32event.CreateMutex(None, False, mutex_name)
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                base = Path(tmp_dir)
                active, desc, pid = check_service_status(port=59130, root_dir=base, mutex_name=mutex_name)
                self.assertTrue(active)
                self.assertIn("互斥锁已占用", desc)
        finally:
            win32api.CloseHandle(h_mutex)

    def test_kill_stale_server_process(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            runtime_dir = base / ".runtime"
            runtime_dir.mkdir(parents=True, exist_ok=True)

            # Dead PID file
            pid_file = runtime_dir / ".server.pid"
            pid_file.write_text("9999999", encoding="utf-8")

            killed = kill_stale_server_process(port=59125, root_dir=base)
            self.assertEqual(killed, [])
            self.assertFalse(pid_file.exists())

    def test_is_mcp_or_related_process_identity(self):
        # Current test runner is python
        self.assertTrue(is_mcp_or_related_process(os.getpid()))
        # Non-existent PID fails closed (returns False)
        self.assertFalse(is_mcp_or_related_process(9999999))
        self.assertFalse(is_mcp_or_related_process(-1))

    def test_read_pids_from_files(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            runtime_dir = base / ".runtime"
            runtime_dir.mkdir(parents=True, exist_ok=True)
            f1 = runtime_dir / ".server.pid"
            f2 = base / ".server.pid"
            f1.write_text("1001", encoding="utf-8")
            f2.write_text("1002", encoding="utf-8")
            pids = read_pids_from_files(runtime_dir, base, ".server.pid")
            self.assertEqual(pids, [1001, 1002])

    def test_stop_mcp_service(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            runtime_dir = base / ".runtime"
            runtime_dir.mkdir(parents=True, exist_ok=True)

            tray_pid_file = runtime_dir / ".tray.pid"
            tray_pid_file.write_text("9999999", encoding="utf-8")

            summary = stop_mcp_service(port=59126, root_dir=base)
            self.assertEqual(summary["status"], "success")
            self.assertEqual(summary["port"], 59126)
            self.assertFalse(tray_pid_file.exists())


if __name__ == "__main__":
    unittest.main()
