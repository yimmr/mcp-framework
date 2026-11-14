import ast
import os
import tempfile
import unittest
from pathlib import Path

from mcp_server_core.cli import (
    cmd_status,
    create_parser,
    get_cloudflared_download_info,
    main as cli_main,
    normalize_package_name,
)


class TestCliModule(unittest.TestCase):
    def test_normalize_package_name(self):
        self.assertEqual(normalize_package_name("my-service"), "my_service")
        self.assertEqual(normalize_package_name("My Service Tool"), "my_service_tool")
        self.assertEqual(normalize_package_name("123-service"), "_123_service")
        self.assertEqual(normalize_package_name("---"), "mcp_service")
        self.assertEqual(normalize_package_name(""), "mcp_service")
        self.assertEqual(normalize_package_name("special!@#$%^&*()name"), "special__________name")

    def test_get_cloudflared_download_info(self):
        url, exe_name = get_cloudflared_download_info()
        self.assertIsInstance(url, str)
        self.assertTrue(url.startswith("https://"))
        self.assertIn("cloudflared", url)
        if os.name == "nt":
            self.assertEqual(exe_name, "cloudflared.exe")
        else:
            self.assertEqual(exe_name, "cloudflared")

    def test_get_cloudflared_download_info_cross_platform(self):
        from unittest.mock import patch

        # Darwin arm64
        with patch("sys.platform", "darwin"), patch("platform.machine", return_value="arm64"):
            url, name = get_cloudflared_download_info()
            self.assertIn("cloudflared-darwin-arm64.tgz", url)
            self.assertEqual(name, "cloudflared")

        # Linux x86_64
        with patch("sys.platform", "linux"), patch("platform.machine", return_value="x86_64"):
            url, name = get_cloudflared_download_info()
            self.assertIn("cloudflared-linux-amd64", url)
            self.assertEqual(name, "cloudflared")

        # Linux aarch64
        with patch("sys.platform", "linux"), patch("platform.machine", return_value="aarch64"):
            url, name = get_cloudflared_download_info()
            self.assertIn("cloudflared-linux-arm64", url)
            self.assertEqual(name, "cloudflared")

        # Windows amd64
        with patch("sys.platform", "win32"), patch("platform.machine", return_value="AMD64"):
            url, name = get_cloudflared_download_info()
            self.assertIn("cloudflared-windows-amd64.exe", url)
            self.assertEqual(name, "cloudflared.exe")

        # Windows arm64
        with patch("sys.platform", "win32"), patch("platform.machine", return_value="arm64"):
            url, name = get_cloudflared_download_info()
            self.assertIn("cloudflared-windows-amd64.exe", url)
            self.assertEqual(name, "cloudflared.exe")

        # Windows 386
        with patch("sys.platform", "win32"), patch("platform.machine", return_value="i386"):
            url, name = get_cloudflared_download_info()
            self.assertIn("cloudflared-windows-386.exe", url)
            self.assertEqual(name, "cloudflared.exe")

    def test_install_dependencies_mocked(self):
        from unittest.mock import patch, MagicMock
        from mcp_server_core.cli import install_dependencies

        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir)
            # Mock uv success
            mock_res = MagicMock(returncode=0)
            with patch("shutil.which", return_value="C:\\path\\to\\uv.exe"), \
                 patch("subprocess.run", return_value=mock_res):
                success = install_dependencies(target)
                self.assertTrue(success)

    def test_create_parser(self):
        parser = create_parser()

        # Parse init command
        args_init = parser.parse_args(["init", "demo", "--port", "9100", "--title", "Demo Title", "--no-install"])
        self.assertEqual(args_init.command, "init")
        self.assertEqual(args_init.name, "demo")
        self.assertEqual(args_init.port, 9100)
        self.assertEqual(args_init.title, "Demo Title")
        self.assertTrue(args_init.no_install)

        # Parse status command
        args_status = parser.parse_args(["status"])
        self.assertEqual(args_status.command, "status")

    def test_cmd_status(self):
        parser = create_parser()
        args = parser.parse_args(["status"])
        ret = cmd_status(args)
        self.assertEqual(ret, 0)

    def test_scaffolded_python_files_are_valid_syntax(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            proj_dir = Path(tmp_dir) / "test-syntax-app"
            ret = cli_main(["init", str(proj_dir), "--port", "8822", "--no-install"])
            self.assertEqual(ret, 0)

            # Inspect all .py files and ensure valid Python syntax
            py_files = list(proj_dir.rglob("*.py"))
            self.assertGreater(len(py_files), 5)
            for py_path in py_files:
                code = py_path.read_text(encoding="utf-8")
                try:
                    ast.parse(code, filename=str(py_path))
                except SyntaxError as e:
                    self.fail(f"Syntax error in generated file {py_path}: {e}")

            # Verify pyproject.toml has clean dependencies without duplicates
            pyproject_content = (proj_dir / "pyproject.toml").read_text(encoding="utf-8")
            self.assertEqual(pyproject_content.count("mcp-server-core[tray]>="), 1)
            self.assertNotIn('"mcp-server-core>=', pyproject_content)

            # Verify .env and .env.example contain standardized MCP_SERVICE_NAME and MCP_SERVICE_TITLE
            env_content = (proj_dir / ".env").read_text(encoding="utf-8")
            self.assertIn("MCP_SERVICE_NAME=test-syntax-app", env_content)
            self.assertIn("MCP_SERVICE_TITLE=Test Syntax App", env_content)

            env_example = (proj_dir / ".env.example").read_text(encoding="utf-8")
            self.assertIn("MCP_SERVICE_NAME=test-syntax-app", env_example)
            self.assertIn("MCP_SERVICE_TITLE=Test Syntax App", env_example)

            # Verify .gitignore contains bin/
            gitignore_content = (proj_dir / ".gitignore").read_text(encoding="utf-8")
            self.assertIn("bin/", gitignore_content)

    def test_shortcut_and_version(self):
        # Version flag exit code 0
        with self.assertRaises(SystemExit) as ctx:
            cli_main(["--version"])
        self.assertEqual(ctx.exception.code, 0)

        # Shortcut invocation
        with tempfile.TemporaryDirectory() as tmp_dir:
            proj_dir = Path(tmp_dir) / "shortcut-app"
            ret = cli_main([str(proj_dir), "--port", "8833", "--no-install"])
            self.assertEqual(ret, 0)
            self.assertTrue((proj_dir / "pyproject.toml").exists())
            self.assertTrue((proj_dir / "shortcut_app" / "server.py").exists())

    def test_cmd_download_cloudflared_direct(self):
        import argparse
        import io
        from unittest.mock import MagicMock, patch
        from mcp_server_core.cli import cmd_download_cloudflared

        with tempfile.TemporaryDirectory() as tmp_dir:
            target_dir = Path(tmp_dir)
            mock_data = b"binary_content_12345"
            mock_resp = io.BytesIO(mock_data)
            mock_resp.headers = {"Content-Length": str(len(mock_data))}

            args = argparse.Namespace(target=str(target_dir))
            with patch("urllib.request.urlopen", return_value=mock_resp), \
                 patch("subprocess.run", return_value=MagicMock(stdout="cloudflared 2026.10")):
                code = cmd_download_cloudflared(args)
                self.assertEqual(code, 0)

                exe_name = "cloudflared.exe" if os.name == "nt" else "cloudflared"
                downloaded = target_dir / exe_name
                self.assertTrue(downloaded.exists())
                self.assertEqual(downloaded.read_bytes(), mock_data)

    def test_cmd_download_cloudflared_tgz(self):
        import argparse
        import io
        import tarfile
        from unittest.mock import MagicMock, patch
        from mcp_server_core.cli import cmd_download_cloudflared

        with tempfile.TemporaryDirectory() as tmp_dir:
            target_dir = Path(tmp_dir)
            exe_name = "cloudflared"

            # Create in-memory tar.gz archive
            tar_buf = io.BytesIO()
            with tarfile.open(fileobj=tar_buf, mode="w:gz") as tar:
                inner_data = b"extracted_darwin_cloudflared_binary"
                info = tarfile.TarInfo(name=exe_name)
                info.size = len(inner_data)
                tar.addfile(info, io.BytesIO(inner_data))

            tar_bytes = tar_buf.getvalue()
            mock_resp = io.BytesIO(tar_bytes)
            mock_resp.headers = {"Content-Length": str(len(tar_bytes))}

            args = argparse.Namespace(target=str(target_dir))
            with patch("mcp_server_core.cli.get_cloudflared_download_info", return_value=("https://fake/cloudflared.tgz", exe_name)), \
                 patch("urllib.request.urlopen", return_value=mock_resp), \
                 patch("subprocess.run", return_value=MagicMock(stdout="cloudflared 2026.10")):
                code = cmd_download_cloudflared(args)
                self.assertEqual(code, 0)

                downloaded = target_dir / exe_name
                self.assertTrue(downloaded.exists())
                self.assertEqual(downloaded.read_bytes(), b"extracted_darwin_cloudflared_binary")


if __name__ == "__main__":
    unittest.main()
