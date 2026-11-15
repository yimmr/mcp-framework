import os
import tempfile
import unittest
from pathlib import Path

from mcp_server_core import (
    ToolResultListDict,
    __version__,
    find_cloudflared,
    is_cloudflared_available,
)
from mcp_server_core.cli import main as cli_main


class TestMcpServerCore(unittest.TestCase):
    def test_version_and_exports(self):
        self.assertEqual(__version__, "0.7.0")
        res = ToolResultListDict([{"name": "demo"}], key="projects")
        self.assertIsInstance(res, dict)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["projects"], [{"name": "demo"}])
        self.assertEqual(res[0], {"name": "demo"})

    def test_cloudflared_resolution(self):
        if not is_cloudflared_available():
            self.skipTest("cloudflared binary not available in test environment")
        resolved = find_cloudflared()
        self.assertTrue(resolved.exists())
        self.assertTrue(str(resolved).endswith("cloudflared.exe") or str(resolved).endswith("cloudflared"))

    def test_cloudflared_custom_override(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            fake_bin = Path(tmp_dir) / ("cloudflared.exe" if os.name == "nt" else "cloudflared")
            fake_bin.touch()
            # Test direct argument
            found = find_cloudflared(fake_bin)
            self.assertEqual(found, fake_bin.resolve())

            # Test env variable
            old_env = os.environ.get("CLOUDFLARED_PATH")
            try:
                os.environ["CLOUDFLARED_PATH"] = str(fake_bin)
                found_env = find_cloudflared()
                self.assertEqual(found_env, fake_bin.resolve())
            finally:
                if old_env is not None:
                    os.environ["CLOUDFLARED_PATH"] = old_env
                else:
                    os.environ.pop("CLOUDFLARED_PATH", None)

    def test_cli_init_scaffold(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            target_proj = Path(tmp_dir) / "sample-service"
            cli_main(["init", str(target_proj), "--port", "8999", "--char", "S", "--color", "#9b59b6", "--no-install"])

            self.assertTrue((target_proj / "pyproject.toml").exists())
            self.assertTrue((target_proj / ".env").exists())
            self.assertTrue((target_proj / "start.bat").exists())
            self.assertTrue((target_proj / "stop.bat").exists())
            self.assertTrue((target_proj / "sample_service" / "server.py").exists())
            self.assertTrue((target_proj / "sample_service" / "config.py").exists())
            self.assertTrue((target_proj / "sample_service" / "tools" / "system.py").exists())
            self.assertTrue((target_proj / "tests" / "test_tools.py").exists())

            env_text = (target_proj / ".env").read_text(encoding="utf-8")
            self.assertIn("MCP_PORT=8999", env_text)
            self.assertIn("MCP_API_KEY=sec_", env_text)

    def test_cli_npx_style_shortcut(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            target_proj = Path(tmp_dir) / "quick-service"
            # Without 'init' keyword, direct project path
            cli_main([str(target_proj), "--port", "9005", "--no-install"])

            self.assertTrue((target_proj / "quick_service" / "server.py").exists())
            self.assertTrue((target_proj / "pyproject.toml").exists())


if __name__ == "__main__":
    unittest.main()
