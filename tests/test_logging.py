"""Unit tests for mcp_server_core.logging and observability subsystems."""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

try:
    from mcp.server.fastmcp import FastMCP
    from mcp.server.fastmcp.exceptions import ToolError
except (ImportError, ModuleNotFoundError):
    from mcp.server.mcpserver import MCPServer as FastMCP
    ToolError = Exception

from mcp_server_core.env import DeploymentEnvConfig
from mcp_server_core.http_server import (
    AccessLogMiddleware,
    TraceContextMiddleware,
    create_mcp_asgi_app,
)
from mcp_server_core.logging import (
    LoggingConfig,
    LogManager,
    TraceLogFilter,
    extract_or_generate_trace_id,
    generate_trace_id,
    get_current_trace_id,
    instrument_fastmcp_server,
    observe_tool,
    reset_current_trace_id,
    sanitize_arguments,
    sanitize_string_value,
    sanitize_value,
    set_current_trace_id,
    setup_logging,
    summarize_tool_result,
)
from mcp_server_core.oauth import LocalOAuthServer


class TestLoggingConfig(unittest.TestCase):
    def test_default_config(self):
        cfg = LoggingConfig()
        self.assertEqual(cfg.log_dir, ".runtime/logs")
        self.assertEqual(cfg.access_filename, "access.log")
        self.assertIsNone(cfg.app_filename)
        self.assertEqual(cfg.error_filename, "error.log")
        self.assertEqual(cfg.level, "INFO")
        self.assertEqual(cfg.max_bytes, 10 * 1024 * 1024)
        self.assertEqual(cfg.backup_count, 5)
        self.assertTrue(cfg.enable_console)
        self.assertTrue(cfg.enable_trace_injection)

    def test_resolve_filenames_and_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = LoggingConfig(log_dir=".runtime/custom_logs")
            resolved_dir = cfg.resolve_log_dir(root)
            self.assertEqual(resolved_dir, (root / ".runtime/custom_logs").resolve())
            self.assertTrue(resolved_dir.exists())

            # App filename default vs dynamic service name
            self.assertEqual(cfg.resolve_app_filename(None), "app.log")
            self.assertEqual(cfg.resolve_app_filename("Codexen Engine"), "codexen_engine.log")

            # App filename explicit override
            cfg2 = LoggingConfig(app_filename="engine.log")
            self.assertEqual(cfg2.resolve_app_filename("Codexen"), "engine.log")

    def test_multi_tier_precedence(self):
        # Tier 4: defaults
        cfg = LoggingConfig.from_dict_and_env()
        self.assertEqual(cfg.log_dir, ".runtime/logs")

        # Tier 3: config dict
        cfg_dict = {
            "dir": ".runtime/dict_logs",
            "filenames": {
                "app": "dict_app.log",
                "access": "dict_access.log",
                "error": "dict_error.log",
            },
            "level": "DEBUG",
            "max_bytes": 5000,
            "backup_count": 2,
            "enable_console": False,
        }
        cfg3 = LoggingConfig.from_dict_and_env(config_dict=cfg_dict)
        self.assertEqual(cfg3.log_dir, ".runtime/dict_logs")
        self.assertEqual(cfg3.app_filename, "dict_app.log")
        self.assertEqual(cfg3.access_filename, "dict_access.log")
        self.assertEqual(cfg3.error_filename, "dict_error.log")
        self.assertEqual(cfg3.level, "DEBUG")
        self.assertEqual(cfg3.max_bytes, 5000)
        self.assertEqual(cfg3.backup_count, 2)
        self.assertFalse(cfg3.enable_console)

        # Tier 2: environment variables override config dict
        with patch.dict(os.environ, {
            "MCP_LOG_DIR": ".runtime/env_logs",
            "MCP_LOG_APP_FILE": "env_app.log",
            "MCP_LOG_LEVEL": "WARNING",
        }):
            cfg2 = LoggingConfig.from_dict_and_env(config_dict=cfg_dict)
            self.assertEqual(cfg2.log_dir, ".runtime/env_logs")
            self.assertEqual(cfg2.app_filename, "env_app.log")
            self.assertEqual(cfg2.level, "WARNING")

        # Tier 1: kwargs override environment variables and config dict
        with patch.dict(os.environ, {"MCP_LOG_DIR": ".runtime/env_logs"}):
            cfg1 = LoggingConfig.from_dict_and_env(
                config_dict=cfg_dict,
                log_dir=".runtime/kwargs_logs",
                level="CRITICAL",
            )
            self.assertEqual(cfg1.log_dir, ".runtime/kwargs_logs")
            self.assertEqual(cfg1.level, "CRITICAL")


class TestSanitizer(unittest.TestCase):
    def test_sensitive_key_masking(self):
        payload = {
            "project_id": "test_proj",
            "api_key": "sec_my_secret_key_123",
            "user_password": "super_secret_password",
            "auth_token": "Bearer abc.def.ghi",
            "nested": {
                "client_secret": "my_client_secret",
                "normal_param": "hello_world",
            },
            "array_items": [
                {"token": "tok_123"},
                {"safe_field": 42},
            ],
        }
        sanitized = sanitize_value(payload)
        self.assertEqual(sanitized["project_id"], "test_proj")
        self.assertEqual(sanitized["api_key"], "***")
        self.assertEqual(sanitized["user_password"], "***")
        self.assertEqual(sanitized["auth_token"], "***")
        self.assertEqual(sanitized["nested"]["client_secret"], "***")
        self.assertEqual(sanitized["nested"]["normal_param"], "hello_world")
        self.assertEqual(sanitized["array_items"][0]["token"], "***")
        self.assertEqual(sanitized["array_items"][1]["safe_field"], 42)

    def test_string_secret_masking(self):
        s1 = "Request failed with Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI"
        masked1 = sanitize_string_value(s1)
        self.assertIn("Bearer ***", masked1)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI", masked1)

        s2 = "Generated temporary secret: sec_9f8e7d6c5b4a3"
        masked2 = sanitize_string_value(s2)
        self.assertIn("sec_***", masked2)
        self.assertNotIn("sec_9f8e7d6c5b4a3", masked2)

    def test_payload_hook(self):
        def custom_hook(tool_name: str, args: dict) -> dict:
            if tool_name == "write_file" and "content" in args:
                return {**args, "content": f"[file_content: {len(args['content'])} chars]"}
            return args

        args = {"path": "test.py", "content": "x = 1\n" * 100}
        res = sanitize_arguments("write_file", args, payload_hook=custom_hook)
        self.assertEqual(res["path"], "test.py")
        self.assertEqual(res["content"], "[file_content: 600 chars]")

    def test_summarize_tool_result(self):
        self.assertEqual(summarize_tool_result(None), "None")
        self.assertIn("str: ok", summarize_tool_result("ok"))
        self.assertIn("status=success", summarize_tool_result({"status": "success", "count": 10}))
        self.assertIn("list: count=3", summarize_tool_result([1, 2, 3]))


class TestTraceContext(unittest.TestCase):
    def test_extract_trace_id_cf_ray(self):
        # ASGI headers format: list of (bytes, bytes)
        headers = [(b"host", b"example.com"), (b"cf-ray", b"8e1a2b3c4d-HKG")]
        tid = extract_or_generate_trace_id(headers)
        self.assertEqual(tid, "8e1a2b3c4d-HKG")

    def test_extract_trace_id_x_request_id(self):
        headers = [(b"x-request-id", b"req_abc123")]
        tid = extract_or_generate_trace_id(headers)
        self.assertEqual(tid, "req_abc123")

    def test_generate_trace_id_fallback(self):
        headers = [(b"host", b"example.com")]
        tid = extract_or_generate_trace_id(headers)
        self.assertTrue(tid.startswith("trace_"))
        self.assertEqual(len(tid), 14)  # "trace_" + 8 hex chars

    def test_contextvar_binding(self):
        self.assertEqual(get_current_trace_id(), "")
        token = set_current_trace_id("trace_xyz")
        try:
            self.assertEqual(get_current_trace_id(), "trace_xyz")
        finally:
            reset_current_trace_id(token)
        self.assertEqual(get_current_trace_id(), "")


class TestLogManagerAndStreams(unittest.TestCase):
    def test_three_stream_separation_and_rotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = LoggingConfig(
                log_dir=".runtime/logs",
                access_filename="access.log",
                app_filename="test_app.log",
                error_filename="error.log",
                max_bytes=1024,  # Small size for rotation test
                backup_count=3,
                enable_console=False,
            )
            mgr = setup_logging(base_dir=root, config=cfg, service_name="test_service")
            try:
                # 1. Log access stream
                access_lg = mgr.get_access_logger()
                access_lg.info('127.0.0.1 - "GET /health HTTP/1.1" 200 1.23ms')

                # 2. Log app stream
                app_lg = mgr.get_app_logger()
                app_lg.info("App standard startup message")

                # 3. Log error stream
                error_lg = mgr.get_error_logger()
                error_lg.error("Critical database connection error simulated")

                # Flush handlers
                for h in mgr._handlers:
                    h.flush()

                # Verify files exist
                self.assertTrue((mgr.log_dir / "access.log").exists())
                self.assertTrue((mgr.log_dir / "test_app.log").exists())
                self.assertTrue((mgr.log_dir / "error.log").exists())

                access_txt = (mgr.log_dir / "access.log").read_text(encoding="utf-8")
                app_txt = (mgr.log_dir / "test_app.log").read_text(encoding="utf-8")
                error_txt = (mgr.log_dir / "error.log").read_text(encoding="utf-8")

                # Access log must contain access record, not app/error messages
                self.assertIn("GET /health", access_txt)
                self.assertNotIn("App standard startup message", access_txt)
                self.assertNotIn("Critical database connection error", access_txt)

                # Error log must contain error message and NOT info message
                self.assertIn("Critical database connection error", error_txt)
                self.assertNotIn("App standard startup message", error_txt)
                self.assertNotIn("GET /health", error_txt)

                # App log contains app info and error
                self.assertIn("App standard startup message", app_txt)
                self.assertIn("Critical database connection error", app_txt)

                # Test rotation by writing repetitive messages
                for _ in range(50):
                    app_lg.info("Rotation pad message line: " + "a" * 80)
                for h in mgr._handlers:
                    h.flush()

                # Check if rotation created backup files
                rotated = list(mgr.log_dir.glob("test_app.log.*"))
                self.assertGreaterEqual(len(rotated), 1)

            finally:
                mgr.close()


class TestHttpMiddlewareIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_trace_context_and_access_log_middleware(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = LoggingConfig(log_dir=".runtime/logs", enable_console=False)
            mgr = setup_logging(base_dir=root, config=cfg, service_name="test_service")

            async def dummy_endpoint(request: Request):
                return JSONResponse({"status": "ok", "trace": get_current_trace_id()})

            app = Starlette(routes=[Route("/test_trace", dummy_endpoint)])
            app.add_middleware(AccessLogMiddleware)
            app.add_middleware(TraceContextMiddleware)

            try:
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app), base_url="http://testserver"
                ) as client:
                    # 1. Request with cf-ray header
                    resp = await client.get("/test_trace", headers={"cf-ray": "8e1a2b3c4d-SJC"})
                    self.assertEqual(resp.status_code, 200)
                    self.assertEqual(resp.headers.get("x-trace-id"), "8e1a2b3c4d-SJC")
                    self.assertEqual(resp.headers.get("cf-ray"), "8e1a2b3c4d-SJC")
                    self.assertEqual(resp.json()["trace"], "8e1a2b3c4d-SJC")

                    # 2. Request without trace headers (auto-generates)
                    resp2 = await client.get("/test_trace")
                    self.assertEqual(resp2.status_code, 200)
                    tid2 = resp2.headers.get("x-trace-id")
                    self.assertTrue(tid2.startswith("trace_"))
                    self.assertEqual(resp2.json()["trace"], tid2)

                # Verify access.log wrote trace IDs
                for h in mgr._handlers:
                    h.flush()

                access_txt = (mgr.log_dir / "access.log").read_text(encoding="utf-8")
                self.assertIn("[trace_id: 8e1a2b3c4d-SJC]", access_txt)
                self.assertIn(f"[trace_id: {tid2}]", access_txt)

            finally:
                mgr.close()


class TestToolAspectInterception(unittest.IsolatedAsyncioTestCase):
    async def test_observe_tool_decorator(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = LoggingConfig(log_dir=".runtime/logs", enable_console=False)
            mgr = setup_logging(base_dir=root, config=cfg, service_name="test_service")

            try:
                @observe_tool()
                def sample_sync_tool(param: str, secret_token: str = "") -> dict:
                    if param == "fail":
                        raise ValueError("simulated tool failure")
                    return {"status": "success", "result": f"processed_{param}"}

                @observe_tool()
                async def sample_async_tool(count: int, password: str = "") -> list:
                    await asyncio.sleep(0.01)
                    return [f"item_{i}" for i in range(count)]

                # 1. Call sync tool successfully
                res1 = sample_sync_tool("alpha", secret_token="sec_token_val")
                self.assertEqual(res1["status"], "success")

                # 2. Call async tool successfully
                res2 = await sample_async_tool(3, password="super_secret")
                self.assertEqual(len(res2), 3)

                # 3. Call sync tool failure
                with self.assertRaises(ValueError):
                    sample_sync_tool("fail")

                for h in mgr._handlers:
                    h.flush()

                app_txt = (mgr.log_dir / "test_service.log").read_text(encoding="utf-8")
                error_txt = (mgr.log_dir / "error.log").read_text(encoding="utf-8")

                # Sanitization check in App log
                self.assertIn('"secret_token": "***"', app_txt)
                self.assertIn('"password": "***"', app_txt)
                self.assertNotIn("sec_token_val", app_txt)
                self.assertNotIn("super_secret", app_txt)

                # Tool lifecycle check
                self.assertIn("Tool started: sample_sync_tool", app_txt)
                self.assertIn("Tool finished: sample_sync_tool", app_txt)
                self.assertIn("Tool started: sample_async_tool", app_txt)
                self.assertIn("Tool finished: sample_async_tool", app_txt)

                # Error check in Error log
                self.assertIn("Tool failed: sample_sync_tool", error_txt)
                self.assertIn("ValueError: simulated tool failure", error_txt)

            finally:
                mgr.close()

    async def test_instrument_fastmcp_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = LoggingConfig(log_dir=".runtime/logs", enable_console=False)
            mgr = setup_logging(base_dir=root, config=cfg, service_name="test_service")

            server = FastMCP("test_fastmcp")

            @server.tool()
            def calculate_square(n: int, auth_key: str = "") -> int:
                if n < 0:
                    raise ValueError("Negative number not allowed")
                return n * n

            # Instrument FastMCP server
            instrument_fastmcp_server(server)

            try:
                # Direct call via server.call_tool
                res = await server.call_tool("calculate_square", {"n": 5, "auth_key": "sec_12345"})
                self.assertIsNotNone(res)

                # Error call via server.call_tool
                with self.assertRaises(Exception) as ctx:
                    await server.call_tool("calculate_square", {"n": -5})

                # Verify exception contains trace_id
                err_str = str(ctx.exception)
                self.assertTrue("trace_id" in err_str or "trace_" in err_str)

                for h in mgr._handlers:
                    h.flush()

                app_txt = (mgr.log_dir / "test_service.log").read_text(encoding="utf-8")
                error_txt = (mgr.log_dir / "error.log").read_text(encoding="utf-8")

                self.assertIn("Tool execution started: calculate_square", app_txt)
                self.assertIn('"auth_key": "***"', app_txt)
                self.assertIn("Tool execution completed: calculate_square", app_txt)
                self.assertIn("Tool execution failed: calculate_square", error_txt)
                self.assertIn("Negative number not allowed", error_txt)

            finally:
                mgr.close()


    def test_logging_dir_containment(self):
        """P2-1 / R-6: Verify log directory containment checks."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            cfg_escape = LoggingConfig(log_dir="../escaped_logs")
            with self.assertRaises(ValueError) as ctx:
                cfg_escape.resolve_log_dir(base)
            self.assertIn("escapes base directory", str(ctx.exception))

            # allow_outside_base=True permits writing outside base_dir
            cfg_allowed = LoggingConfig(log_dir="../escaped_logs", allow_outside_base=True)
            resolved = cfg_allowed.resolve_log_dir(base)
            self.assertTrue(resolved.exists())
            import shutil
            if resolved.exists():
                shutil.rmtree(resolved)

    def test_sensitive_key_boundary_matching(self):
        """P3-3: Verify authorized_paths is not false-positively masked as sensitive."""
        from mcp_server_core.logging.sanitizer import is_sensitive_key, sanitize_arguments
        self.assertFalse(is_sensitive_key("authorized_paths"))
        self.assertTrue(is_sensitive_key("auth"))
        self.assertTrue(is_sensitive_key("auth_token"))
        self.assertTrue(is_sensitive_key("user_auth"))
        self.assertTrue(is_sensitive_key("api_key"))

        args = {
            "authorized_paths": ["/home/user/project", "/tmp/docs"],
            "auth_token": "secret_abc_123",
            "normal_arg": "hello",
        }
        sanitized = sanitize_arguments("test_tool", args)
        self.assertEqual(sanitized["authorized_paths"], ["/home/user/project", "/tmp/docs"])
        self.assertEqual(sanitized["auth_token"], "***")
        self.assertEqual(sanitized["normal_arg"], "hello")

    async def test_real_mcp_streamable_http_instrumentation_and_per_request_trace(self):
        """P1-1 / P1-2 / R-1 / R-2: Real MCP transport trace propagation & tool aspect execution."""
        import httpx
        from mcp_server_core.http_server import create_mcp_asgi_app
        from mcp_server_core.env import DeploymentEnvConfig

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = LoggingConfig(log_dir=".runtime/logs", enable_console=False)
            mgr = setup_logging(base_dir=root, config=cfg, service_name="generic_service")

            server = FastMCP("generic_mcp")

            # Uninstrumented tool definitions (no manual observe_tool decorator)
            @server.tool()
            def ping(echo: str = "pong", auth_key: str = "") -> dict[str, str]:
                return {"reply": echo}

            @server.tool()
            def deliberate_failure(code: int) -> str:
                raise RuntimeError(f"Simulated crash with code {code}")

            instrument_fastmcp_server(server)

            env_cfg = DeploymentEnvConfig(require_auth=False)
            asgi_app = create_mcp_asgi_app(server=server, env_cfg=env_cfg, oauth_server=None, require_auth=False)

            headers_common = {"accept": "application/json, text/event-stream"}

            try:
                async with asgi_app.router.lifespan_context(asgi_app):
                    async with httpx.AsyncClient(
                        transport=httpx.ASGITransport(app=asgi_app),
                        base_url="http://localhost:8788",
                    ) as client:
                        # 1. Initialize with cf-ray: ray-init-AAA
                        init_res = await client.post(
                            "/mcp",
                            json={
                                "jsonrpc": "2.0",
                                "id": "init-1",
                                "method": "initialize",
                                "params": {
                                    "protocolVersion": "2024-11-05",
                                    "capabilities": {},
                                    "clientInfo": {"name": "test-client", "version": "1.0"},
                                },
                            },
                            headers={**headers_common, "cf-ray": "ray-init-AAA"},
                        )
                        self.assertEqual(init_res.status_code, 200)
                        session_id = init_res.headers.get("mcp-session-id")
                        self.assertIsNotNone(session_id)

                        # 2. Initialized notification
                        notif_res = await client.post(
                            "/mcp",
                            json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                            headers={**headers_common, "mcp-session-id": session_id, "cf-ray": "ray-notif-BBB"},
                        )
                        self.assertEqual(notif_res.status_code, 202)

                        # 3. Call tool: ping with cf-ray: ray-ping-CCC
                        call1_res = await client.post(
                            "/mcp",
                            json={
                                "jsonrpc": "2.0",
                                "id": "call-1",
                                "method": "tools/call",
                                "params": {"name": "ping", "arguments": {"echo": "hello", "auth_key": "sec_token1"}},
                            },
                            headers={**headers_common, "mcp-session-id": session_id, "cf-ray": "ray-ping-CCC"},
                        )
                        self.assertEqual(call1_res.status_code, 200)

                        # 4. Call tool: deliberate_failure with cf-ray: ray-err-DDD
                        call2_res = await client.post(
                            "/mcp",
                            json={
                                "jsonrpc": "2.0",
                                "id": "call-2",
                                "method": "tools/call",
                                "params": {"name": "deliberate_failure", "arguments": {"code": 500}},
                            },
                            headers={**headers_common, "mcp-session-id": session_id, "cf-ray": "ray-err-DDD"},
                        )
                        self.assertEqual(call2_res.status_code, 200)

                        # Verify client error body contains trace_id matching the failure request ray
                        call2_text = call2_res.text
                        self.assertIn("isError", call2_text)
                        self.assertIn("trace_id: ray-err-DDD", call2_text)
                        self.assertNotIn("ray-init-AAA", call2_text)

                for h in mgr._handlers:
                    h.flush()

                access_txt = (mgr.log_dir / "access.log").read_text(encoding="utf-8")
                app_txt = (mgr.log_dir / "generic_service.log").read_text(encoding="utf-8")
                error_txt = (mgr.log_dir / "error.log").read_text(encoding="utf-8")

                # Access log verification
                self.assertIn("[trace_id: ray-init-AAA]", access_txt)
                self.assertIn("[trace_id: ray-ping-CCC]", access_txt)
                self.assertIn("[trace_id: ray-err-DDD]", access_txt)

                # App log verification: ping tool execution tied to ray-ping-CCC, NOT ray-init-AAA
                self.assertIn("Tool execution started: ping", app_txt)
                self.assertIn("[trace_id: ray-ping-CCC]", app_txt)
                self.assertIn("Tool execution completed: ping", app_txt)
                self.assertIn('"auth_key": "***"', app_txt)

                # Error log verification: failure tied to ray-err-DDD, NOT ray-init-AAA
                self.assertIn("Tool execution failed: deliberate_failure", error_txt)
                self.assertIn("[trace_id: ray-err-DDD]", error_txt)
                self.assertIn("Simulated crash with code 500", error_txt)
                self.assertNotIn("[trace_id: ray-init-AAA] Tool execution failed", error_txt)

            finally:
                mgr.close()


if __name__ == "__main__":
    unittest.main()
