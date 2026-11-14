import functools
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Route

from mcp_server_core.cli import normalize_package_name
from mcp_server_core.metadata import ServiceMetadata
from mcp_server_core.oauth import (
    AuthRateLimiter,
    LocalOAuthServer,
    oauth_authorize_endpoint,
    oauth_register_endpoint,
    oauth_token_endpoint,
)
from mcp_server_core.server import run_mcp_server
from mcp_server_core.tunnel import get_tunnel_metrics_port, get_tunnel_token


class TestAuditEnhancements(unittest.IsolatedAsyncioTestCase):
    def test_normalize_package_name_keywords(self):
        # Python keywords must not produce invalid package names
        self.assertEqual(normalize_package_name("pass"), "pass_mcp")
        self.assertEqual(normalize_package_name("def"), "def_mcp")
        self.assertEqual(normalize_package_name("class"), "class_mcp")
        self.assertEqual(normalize_package_name("import"), "import_mcp")
        self.assertEqual(normalize_package_name("return"), "return_mcp")

    def test_metadata_dynamic_core_version(self):
        meta = ServiceMetadata(service_name="audit_test")
        ua = meta.get_user_agent()
        self.assertIn("mcp-server-core/0.6.0", ua)

        # Custom core version override
        custom_ua = meta.get_user_agent(core_version="1.0.0")
        self.assertIn("mcp-server-core/1.0.0", custom_ua)

    def test_auth_rate_limiter_thread_safety(self):
        limiter = AuthRateLimiter(max_attempts=100, window_seconds=60, lockout_seconds=120)
        errors = []

        def worker(worker_id: int):
            try:
                ip = f"10.0.0.{worker_id % 3}"
                for _ in range(50):
                    limiter.record_failure(ip)
                    limiter.is_locked_out(ip)
                    limiter.check_dcr_rate_limit(ip)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Concurrent rate limiter errors: {errors}")

    def test_local_oauth_server_get_client_and_cache(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_client_cache.db"
            server = LocalOAuthServer(admin_password="sec_admin_pass", db_path=db_path)

            # Test get_client when empty
            self.assertIsNone(server.get_client(""))
            self.assertIsNone(server.get_client("non_existent_client"))

            # Register client
            metadata = {
                "client_name": "Audited Client",
                "redirect_uris": ["https://my.callback.org/oauth"],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
            }
            reg = server.register_client(metadata)
            client_id = reg["client_id"]

            # Retrieve client
            client_data = server.get_client(client_id)
            self.assertIsNotNone(client_data)
            self.assertEqual(client_data["client_name"], "Audited Client")
            self.assertEqual(client_data["redirect_uris"], ["https://my.callback.org/oauth"])

            import hashlib
            from mcp_server_core.oauth import base64url_encode
            verifier = "test_verifier_123456789012345678901234567890"
            digest = hashlib.sha256(verifier.encode("ascii")).digest()
            challenge = base64url_encode(digest)

            # Create code & exchange
            code = server.create_auth_code(
                client_id=client_id,
                redirect_uri="https://my.callback.org/oauth",
                code_challenge=challenge,
                code_challenge_method="S256",
            )

            # Mismatched redirect_uri during token exchange MUST raise ValueError
            with self.assertRaises(ValueError) as ctx:
                server.exchange_code_for_token(
                    code=code,
                    client_id=client_id,
                    redirect_uri="https://attacker.com/oauth",
                    code_verifier=verifier,
                )
            self.assertIn("redirect_uri mismatch", str(ctx.exception))

            # Matching redirect_uri succeeds
            tok_resp = server.exchange_code_for_token(
                code=code,
                client_id=client_id,
                redirect_uri="https://my.callback.org/oauth",
                code_verifier=verifier,
            )
            token = tok_resp["access_token"]

            # Token validation hits cache
            self.assertTrue(server.is_token_valid(token))
            self.assertIn(token, server._token_cache)

    async def test_oauth_endpoints_hardening(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_endpoints_hardening.db"
            server = LocalOAuthServer(admin_password="sec_pwd_123", db_path=db_path)

            # Register client with specific redirect_uri
            reg = server.register_client({
                "client_name": "Hardened Client",
                "redirect_uris": ["https://valid.client.com/callback"],
            })
            client_id = reg["client_id"]

            async def dummy_endpoint(request: Request):
                return None

            app = Starlette()

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://testserver"
            ) as client:
                # 1. Non-dict JSON in /oauth/register must not crash with 500
                req_register_bad = Request({
                    "type": "http",
                    "method": "POST",
                    "headers": [(b"content-type", b"application/json")],
                    "client": ("127.0.0.1", 1234),
                })
                # Mock request.json to return a list instead of dict
                req_register_bad._json = ["not", "a", "dict"]
                resp_reg = await oauth_register_endpoint(req_register_bad, server)
                self.assertEqual(resp_reg.status_code, 201)

                # 2. Dangerous redirect_uri schemes in /oauth/authorize must be rejected
                for dangerous_scheme in [
                    "javascript:alert(1)",
                    "data:text/html,<script>alert(1)</script>",
                    "vbscript:msgbox(1)",
                ]:
                    req_auth_bad = Request({
                        "type": "http",
                        "method": "POST",
                        "headers": [(b"content-type", b"application/x-www-form-urlencoded")],
                        "query_string": b"",
                        "client": ("127.0.0.1", 1234),
                    })
                    req_auth_bad._form = {
                        "client_id": client_id,
                        "redirect_uri": dangerous_scheme,
                        "password": "sec_pwd_123",
                    }
                    resp_auth_bad = await oauth_authorize_endpoint(req_auth_bad, server)
                    self.assertEqual(resp_auth_bad.status_code, 400)

                # 3. Redirect URI mismatch against registered client redirect_uris must be rejected
                req_auth_mismatch = Request({
                    "type": "http",
                    "method": "POST",
                    "headers": [(b"content-type", b"application/x-www-form-urlencoded")],
                    "query_string": b"",
                    "client": ("127.0.0.1", 1234),
                })
                req_auth_mismatch._form = {
                    "client_id": client_id,
                    "redirect_uri": "https://unauthorized-domain.com/callback",
                    "password": "sec_pwd_123",
                }
                resp_auth_mismatch = await oauth_authorize_endpoint(req_auth_mismatch, server)
                self.assertEqual(resp_auth_mismatch.status_code, 400)

                # 4. Non-dict JSON in /oauth/token must not crash with 500
                req_token_bad = Request({
                    "type": "http",
                    "method": "POST",
                    "headers": [(b"content-type", b"application/json")],
                    "client": ("127.0.0.1", 1234),
                })
                req_token_bad._json = ["invalid_json_payload"]
                resp_token = await oauth_token_endpoint(req_token_bad, server)
                self.assertEqual(resp_token.status_code, 400)

    def test_run_mcp_server_custom_config_path(self):
        mcp = MagicMock()
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            custom_env = base / "custom.env"
            custom_env.write_text("MCP_PORT=7766\nMCP_API_KEY=sec_from_custom_config\n", encoding="utf-8")

            with patch.dict(os.environ, {}, clear=False):
                with patch("anyio.run") as mock_anyio_run:
                    run_mcp_server(
                        server=mcp,
                        base_dir=base,
                        service_name="custom_cfg_test",
                        cli_args=["-c", str(custom_env), "--no-tunnel"],
                    )
                    self.assertTrue(mock_anyio_run.called)
                    args, _ = mock_anyio_run.call_args
                    if isinstance(args[0], functools.partial):
                        env_cfg = args[0].keywords["env_cfg"]
                    else:
                        env_cfg = args[2]
                    self.assertEqual(env_cfg.port, 7766)
                    self.assertEqual(env_cfg.api_key, "sec_from_custom_config")

    def test_tunnel_metrics_port_and_token_base_dir(self):
        # 1. Metrics port dynamic resolution
        old_metrics = os.environ.get("CLOUDFLARE_METRICS_PORT")
        try:
            os.environ["CLOUDFLARE_METRICS_PORT"] = "29999"
            self.assertEqual(get_tunnel_metrics_port(), 29999)
        finally:
            if old_metrics is not None:
                os.environ["CLOUDFLARE_METRICS_PORT"] = old_metrics
            else:
                os.environ.pop("CLOUDFLARE_METRICS_PORT", None)

        # 2. get_tunnel_token with base_dir
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            (base / ".env").write_text("CLOUDFLARE_TUNNEL_TOKEN=token_from_base_dir\n", encoding="utf-8")
            old_tok = os.environ.pop("CLOUDFLARE_TUNNEL_TOKEN", None)
            try:
                found_tok = get_tunnel_token(base_dir=base)
                self.assertEqual(found_tok, "token_from_base_dir")
            finally:
                if old_tok is not None:
                    os.environ["CLOUDFLARE_TUNNEL_TOKEN"] = old_tok

    async def test_no_cache_middleware_and_cors_headers(self):
        from mcp_server_core.http_server import NoCacheMiddleware
        from starlette.responses import PlainTextResponse

        app = Starlette(
            routes=[
                Route("/health", lambda r: PlainTextResponse("OK")),
            ]
        )
        app.add_middleware(NoCacheMiddleware)

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/health")
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.text, "OK")
            self.assertIn("no-store", resp.headers.get("cache-control", ""))
            self.assertEqual(resp.headers.get("pragma"), "no-cache")
            self.assertEqual(resp.headers.get("expires"), "0")

    def test_get_server_public_url_and_strict_pkce_and_preset_prune(self):
        from mcp_server_core.env import DeploymentEnvConfig
        from mcp_server_core.oauth import get_server_public_url, verify_pkce

        # 1. Test get_server_public_url with env_cfg
        req = MagicMock(spec=Request)
        req.headers = {"x-forwarded-proto": "https", "x-forwarded-host": "mcp.mycustomdomain.com"}
        req.client = MagicMock(host="8.8.8.8")
        req.url = MagicMock(scheme="http", netloc="127.0.0.1:8788")

        cfg_untrusted = DeploymentEnvConfig(trust_proxy_headers=False)
        url_untrusted = get_server_public_url(req, env_cfg=cfg_untrusted)
        self.assertEqual(url_untrusted, "http://127.0.0.1:8788")

        cfg_trusted = DeploymentEnvConfig(trust_proxy_headers=True)
        url_trusted = get_server_public_url(req, env_cfg=cfg_trusted)
        self.assertEqual(url_trusted, "https://mcp.mycustomdomain.com")

        # 2. Test strict PKCE length check (43 - 128 chars)
        cfg_strict_pkce = DeploymentEnvConfig(oauth_strict_pkce=True)
        short_verifier = "a" * 42
        valid_verifier = "a" * 43
        long_verifier = "a" * 129
        self.assertFalse(verify_pkce(short_verifier, short_verifier, method="plain", allow_plain=True, env_cfg=cfg_strict_pkce))
        self.assertTrue(verify_pkce(valid_verifier, valid_verifier, method="plain", allow_plain=True, env_cfg=cfg_strict_pkce))
        self.assertFalse(verify_pkce(long_verifier, long_verifier, method="plain", allow_plain=True, env_cfg=cfg_strict_pkce))

        # 3. Test preset client protection when table reaches 200
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_file = Path(tmp_dir) / "prune_test.db"
            cfg_preset = DeploymentEnvConfig(preset_client_id="my_custom_ai_agent")
            server = LocalOAuthServer(admin_password="sec", db_path=db_file, config=cfg_preset)

            # Insert custom preset client
            server.register_client({
                "client_id": "my_custom_ai_agent",
                "client_name": "My Custom AI Agent",
                "redirect_uris": ["https://my.ai.com/cb"],
            })
            # Insert 205 dummy clients
            for i in range(205):
                server.register_client({
                    "client_name": f"Dummy {i}",
                    "redirect_uris": [f"https://dummy{i}.com/cb"],
                })

            # Custom preset client MUST NOT be pruned
            self.assertIsNotNone(server.get_client("my_custom_ai_agent"))


if __name__ == "__main__":
    unittest.main()
