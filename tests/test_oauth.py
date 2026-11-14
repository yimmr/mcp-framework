import hashlib
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from starlette.requests import Request

from mcp_server_core.oauth import (
    AuthRateLimiter,
    LocalOAuthServer,
    base64url_encode,
    get_client_ip,
    is_uri_allowed_for_client,
    oauth_authorization_server_metadata_endpoint,
    oauth_authorize_endpoint,
    oauth_register_endpoint,
    validate_redirect_uri,
    verify_pkce,
)


class TestOAuthModule(unittest.TestCase):
    def test_base64url_encode(self):
        self.assertEqual(base64url_encode(b""), "")
        self.assertEqual(base64url_encode(b"hello world"), "aGVsbG8gd29ybGQ")
        # Ensure no padding '='
        for b in [b"a", b"ab", b"abc", b"abcd"]:
            encoded = base64url_encode(b)
            self.assertFalse(encoded.endswith("="))

    def test_verify_pkce(self):
        # 1. Plain (rejected by default, allowed with opt-in)
        self.assertFalse(verify_pkce("my_verifier", "my_verifier", method="plain"))
        with unittest.mock.patch.dict("os.environ", {"MCP_OAUTH_ALLOW_PLAIN_PKCE": "1"}):
            self.assertTrue(verify_pkce("my_verifier", "my_verifier", method="plain"))
            self.assertFalse(verify_pkce("my_verifier", "wrong_challenge", method="plain"))

        # 2. RFC 7636 Appendix B test vector for S256
        code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        self.assertTrue(verify_pkce(code_verifier, expected_challenge, method="S256"))
        self.assertFalse(verify_pkce("tampered_verifier", expected_challenge, method="S256"))

        # 3. Invalid method
        self.assertFalse(verify_pkce("foo", "foo", method="unsupported"))

    def test_get_client_ip(self):
        # 1. Cloudflare header
        req_cf = MagicMock(spec=Request)
        req_cf.headers = {"cf-connecting-ip": "203.0.113.195"}
        self.assertEqual(get_client_ip(req_cf), "203.0.113.195")

        # 2. X-Forwarded-For with multiple proxies
        req_xff = MagicMock(spec=Request)
        req_xff.headers = {"x-forwarded-for": "198.51.100.42, 10.0.0.1"}
        self.assertEqual(get_client_ip(req_xff), "198.51.100.42")

        # 3. Direct client
        req_direct = MagicMock(spec=Request)
        req_direct.headers = {}
        req_direct.client = MagicMock(host="192.168.1.10")
        self.assertEqual(get_client_ip(req_direct), "192.168.1.10")

        # 4. Fallback
        req_none = MagicMock(spec=Request)
        req_none.headers = {}
        req_none.client = None
        self.assertEqual(get_client_ip(req_none), "127.0.0.1")

    def test_auth_rate_limiter(self):
        limiter = AuthRateLimiter(max_attempts=3, window_seconds=60, lockout_seconds=120)
        ip = "192.0.2.1"

        # Initially not locked
        locked, _ = limiter.is_locked_out(ip)
        self.assertFalse(locked)

        # 1st failure
        locked, _, remaining = limiter.record_failure(ip)
        self.assertFalse(locked)
        self.assertEqual(remaining, 2)

        # 2nd failure
        locked, _, remaining = limiter.record_failure(ip)
        self.assertFalse(locked)
        self.assertEqual(remaining, 1)

        # 3rd failure -> Lockout!
        locked, lockout_secs, remaining = limiter.record_failure(ip)
        self.assertTrue(locked)
        self.assertEqual(lockout_secs, 120)
        self.assertEqual(remaining, 0)

        # Verify is_locked_out
        is_locked, remaining_secs = limiter.is_locked_out(ip)
        self.assertTrue(is_locked)
        self.assertGreater(remaining_secs, 0)

        # Success clears lockout
        limiter.record_success(ip)
        is_locked, _ = limiter.is_locked_out(ip)
        self.assertFalse(is_locked)

    def test_auth_rate_limiter_dcr(self):
        limiter = AuthRateLimiter()
        ip = "192.0.2.2"
        # Fast registration check
        for _ in range(5):
            self.assertTrue(limiter.check_dcr_rate_limit(ip, max_dcr_per_hour=5))
        # 6th should exceed
        self.assertFalse(limiter.check_dcr_rate_limit(ip, max_dcr_per_hour=5))

    def test_local_oauth_server_crud_and_tokens(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_oauth.db"
            server = LocalOAuthServer(admin_password="sec_admin_password_123", db_path=db_path)

            # 1. Admin password validation
            self.assertTrue(server.is_token_valid("sec_admin_password_123"))
            self.assertFalse(server.is_token_valid("wrong_password"))
            self.assertFalse(server.is_token_valid(""))

            # 2. Dynamic Client Registration
            client_metadata = {
                "client_name": "Test Client",
                "redirect_uris": ["https://oauth.pstmn.io/v1/callback"],
            }
            client_record = server.register_client(client_metadata)
            self.assertTrue(client_record["client_id"].startswith("mcp_client_"))
            self.assertTrue(client_record["client_secret"].startswith("mcp_sec_"))
            self.assertEqual(client_record["client_name"], "Test Client")

            # 3. Create Auth Code with PKCE
            code_verifier = "test_code_verifier_1234567890_abcdefghij"
            digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
            code_challenge = base64url_encode(digest)

            auth_code = server.create_auth_code(
                client_id=client_record["client_id"],
                redirect_uri="https://oauth.pstmn.io/v1/callback",
                code_challenge=code_challenge,
                code_challenge_method="S256",
                scope="mcp:read",
            )
            self.assertTrue(auth_code.startswith("auth_code_"))

            # 4. Exchange with wrong verifier -> fails
            with self.assertRaises(ValueError) as ctx:
                server.exchange_code_for_token(
                    code=auth_code,
                    client_id=client_record["client_id"],
                    redirect_uri="https://oauth.pstmn.io/v1/callback",
                    code_verifier="wrong_verifier",
                )
            self.assertIn("PKCE", str(ctx.exception))

            # 5. Exchange with correct verifier -> succeeds
            token_resp = server.exchange_code_for_token(
                code=auth_code,
                client_id=client_record["client_id"],
                redirect_uri="https://oauth.pstmn.io/v1/callback",
                code_verifier=code_verifier,
            )
            self.assertTrue(token_resp["access_token"].startswith("mcp_tok_"))
            self.assertEqual(token_resp["token_type"], "Bearer")
            self.assertEqual(token_resp["client_id"], client_record["client_id"])

            # 6. Verify token is now valid
            self.assertTrue(server.is_token_valid(token_resp["access_token"]))

            # 7. Code cannot be reused (one-time use)
            with self.assertRaises(ValueError) as ctx:
                server.exchange_code_for_token(
                    code=auth_code,
                    client_id=client_record["client_id"],
                    redirect_uri="https://oauth.pstmn.io/v1/callback",
                    code_verifier=code_verifier,
                )
            self.assertIn("Invalid or expired", str(ctx.exception))

    def test_local_oauth_server_token_expiry(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_oauth_expiry.db"
            server = LocalOAuthServer(admin_password="admin", db_path=db_path)

            now = time.time()
            expired_token = "mcp_tok_expired"
            with server._db_conn() as conn:
                conn.execute(
                    "INSERT INTO oauth_tokens (access_token, token_type, expires_in, expires_at, created_at, scope, client_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (expired_token, "Bearer", 10, now - 100, now - 110, "mcp:read", "client1"),
                )

            # Should be invalid and automatically pruned
            self.assertFalse(server.is_token_valid(expired_token))
            with server._db_conn() as conn:
                row = conn.execute("SELECT * FROM oauth_tokens WHERE access_token = ?", (expired_token,)).fetchone()
                self.assertIsNone(row)

    def test_configurable_rate_limiter_and_scopes_and_preset_client(self):
        import os
        from mcp_server_core.oauth import get_oauth_issuer, get_oauth_scopes, DEFAULT_OAUTH_SCOPES

        os.environ.pop("MCP_OAUTH_SCOPES", None)
        os.environ.pop("MCP_OAUTH_ISSUER", None)

        # 1. Test scopes resolution
        self.assertEqual(get_oauth_scopes(), DEFAULT_OAUTH_SCOPES)
        self.assertEqual(get_oauth_scopes(["custom:scope"]), ["custom:scope"])

        os.environ["MCP_OAUTH_SCOPES"] = "env:one, env:two"
        try:
            self.assertEqual(get_oauth_scopes(), ["env:one", "env:two"])
        finally:
            os.environ.pop("MCP_OAUTH_SCOPES", None)

        # 2. Test issuer resolution
        req_mock = MagicMock(spec=Request)
        req_mock.headers = {"x-forwarded-proto": "https", "host": "mcp.example.com"}
        req_mock.url.netloc = "mcp.example.com"

        self.assertEqual(get_oauth_issuer(req_mock), "https://mcp.example.com")

        os.environ["MCP_OAUTH_ISSUER"] = "https://custom-issuer.org"
        try:
            self.assertEqual(get_oauth_issuer(req_mock), "https://custom-issuer.org")
        finally:
            os.environ.pop("MCP_OAUTH_ISSUER", None)

        # 3. Test custom preset client ID and custom rate limiter in LocalOAuthServer
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_preset.db"
            os.environ["MCP_PRESET_CLIENT_ID"] = "claude_agent"
            os.environ["MCP_PRESET_CLIENT_NAME"] = "Claude Desktop"
            try:
                server = LocalOAuthServer(
                    admin_password="sec_pwd",
                    db_path=db_path,
                    max_auth_attempts=3,
                    auth_lockout_secs=300.0,
                )
                self.assertEqual(server.rate_limiter.max_attempts, 3)
                self.assertEqual(server.rate_limiter.lockout_seconds, 300.0)

                with server._db_conn() as conn:
                    row = conn.execute(
                        "SELECT client_name FROM oauth_clients WHERE client_id = 'claude_agent'"
                    ).fetchone()
                    self.assertIsNotNone(row)
                    self.assertEqual(row["client_name"], "Claude Desktop")
            finally:
                os.environ.pop("MCP_PRESET_CLIENT_ID", None)
                os.environ.pop("MCP_PRESET_CLIENT_NAME", None)

    def test_validate_redirect_uri_schemes_and_rules(self):
        # 1. Valid URIs
        self.assertTrue(validate_redirect_uri("https://example.com/callback")[0])
        self.assertTrue(validate_redirect_uri("http://127.0.0.1:8000/callback")[0])
        self.assertTrue(validate_redirect_uri("http://localhost/callback")[0])
        self.assertTrue(validate_redirect_uri("http://[::1]:9000/callback")[0])

        # 2. Non-loopback HTTP
        ok, err = validate_redirect_uri("http://evil.com/callback")
        self.assertFalse(ok)
        self.assertIn("loopback", err)

        # 3. Dangerous schemes
        for dangerous in ["javascript:alert(1)", "data:text/html,abc", "vbscript:msgbox", "file:///etc/passwd"]:
            ok, err = validate_redirect_uri(dangerous)
            self.assertFalse(ok)
            self.assertIn("Dangerous", err)

        # 4. Fragment forbidden
        ok, err = validate_redirect_uri("https://example.com/callback#token=123")
        self.assertFalse(ok)
        self.assertIn("fragment", err)

        # 5. Overlength forbidden
        ok, err = validate_redirect_uri("https://example.com/" + "a" * 2050)
        self.assertFalse(ok)
        self.assertIn("length", err)

    def test_preset_client_redirect_whitelist(self):
        # Official ChatGPT callbacks allowed
        self.assertTrue(is_uri_allowed_for_client("chatgpt", "https://chatgpt.com/connector_platform_oauth_redirect", None))
        self.assertTrue(is_uri_allowed_for_client("chatgpt", "https://chatgpt.com/connector/oauth/c-12345", None))
        self.assertTrue(is_uri_allowed_for_client("chatgpt", "http://127.0.0.1:8788/callback", None))

        # Arbitrary external callback rejected for chatgpt
        self.assertFalse(is_uri_allowed_for_client("chatgpt", "https://evil.com/callback", None))

        # Extended whitelist via MCP_ALLOWED_REDIRECT_URIS
        with unittest.mock.patch.dict("os.environ", {"MCP_ALLOWED_REDIRECT_URIS": "https://custom.app/cb, https://partner.org/cb"}):
            self.assertTrue(is_uri_allowed_for_client("chatgpt", "https://custom.app/cb", None))
            self.assertTrue(is_uri_allowed_for_client("chatgpt", "https://partner.org/cb", None))
            self.assertFalse(is_uri_allowed_for_client("chatgpt", "https://other.com/cb", None))

    def test_trusted_proxy_header_handling(self):
        # Peer is 127.0.0.1 (trusted) -> trusts header
        req_loopback = MagicMock(spec=Request)
        req_loopback.client = MagicMock(host="127.0.0.1")
        req_loopback.headers = {"x-forwarded-for": "10.10.10.10, 1.1.1.1"}
        self.assertEqual(get_client_ip(req_loopback), "10.10.10.10")

        # Peer is private 192.168.1.100 -> trusts header
        req_private = MagicMock(spec=Request)
        req_private.client = MagicMock(host="192.168.1.100")
        req_private.headers = {"cf-connecting-ip": "1.2.3.4"}
        self.assertEqual(get_client_ip(req_private), "1.2.3.4")

        # Peer is public 8.8.8.8 -> untrusted, ignores header!
        req_public = MagicMock(spec=Request)
        req_public.client = MagicMock(host="8.8.8.8")
        req_public.headers = {"cf-connecting-ip": "1.2.3.4", "x-forwarded-for": "5.6.7.8"}
        self.assertEqual(get_client_ip(req_public), "8.8.8.8")

        # Peer is public but MCP_TRUST_PROXY_HEADERS=1 -> trusts header
        with unittest.mock.patch.dict("os.environ", {"MCP_TRUST_PROXY_HEADERS": "1"}):
            self.assertEqual(get_client_ip(req_public), "1.2.3.4")

    def test_metadata_s256_only_and_no_jwks(self):
        import asyncio
        req = MagicMock(spec=Request)
        req.headers = {}
        req.client = None
        req.url = MagicMock(scheme="http", netloc="127.0.0.1:8788")

        # Default: S256 only, no jwks_uri, no refresh_token in discovery document
        resp = asyncio.run(oauth_authorization_server_metadata_endpoint(req))
        import json
        data = json.loads(resp.body.decode("utf-8"))
        self.assertEqual(data["code_challenge_methods_supported"], ["S256"])
        self.assertEqual(data["grant_types_supported"], ["authorization_code"])
        self.assertEqual(data["token_endpoint_auth_methods_supported"], ["none"])
        self.assertNotIn("refresh_token", data["grant_types_supported"])
        self.assertNotIn("jwks_uri", data)

        # Opt-in plain PKCE
        with unittest.mock.patch.dict("os.environ", {"MCP_OAUTH_ALLOW_PLAIN_PKCE": "1"}):
            resp2 = asyncio.run(oauth_authorization_server_metadata_endpoint(req))
            data2 = json.loads(resp2.body.decode("utf-8"))
            self.assertEqual(data2["code_challenge_methods_supported"], ["S256", "plain"])

    def test_dcr_payload_and_uri_validation(self):
        import asyncio
        import httpx
        from starlette.applications import Starlette
        from starlette.routing import Route

        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_dcr_limits.db"
            server = LocalOAuthServer(admin_password="sec", db_path=db_path)

            async def register_endpoint(req):
                return await oauth_register_endpoint(req, server)

            app = Starlette(routes=[
                Route("/oauth/register", register_endpoint, methods=["POST"])
            ])

            async def _run():
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
                    # 1. Payload Content-Length > 64KB rejected with 413
                    resp_huge = await client.post("/oauth/register", content=b"{}", headers={"content-length": "70000"})
                    self.assertEqual(resp_huge.status_code, 413)

                    # 2. Chunked streaming request > 64KB rejected with 413
                    async def chunk_gen():
                        for _ in range(70):
                            yield b"x" * 1024

                    resp_stream = await client.post(
                        "/oauth/register", content=chunk_gen(), headers={"content-type": "application/json"}
                    )
                    self.assertEqual(resp_stream.status_code, 413)

                    # 3. DCR with dangerous scheme rejected with 400
                    resp_bad_uri = await client.post(
                        "/oauth/register", json={"client_name": "x", "redirect_uris": ["javascript:alert(1)"]}
                    )
                    self.assertEqual(resp_bad_uri.status_code, 400)

                    # 4. Valid registration succeeds with 201
                    resp_ok = await client.post(
                        "/oauth/register", json={"client_name": "valid_app", "redirect_uris": ["https://app.example.com/cb"]}
                    )
                    self.assertEqual(resp_ok.status_code, 201)
                    self.assertIn("client_id", resp_ok.json())

            asyncio.run(_run())

    def test_strict_client_id_enforcement_on_token_exchange(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_strict_cid.db"
            server = LocalOAuthServer(admin_password="sec", db_path=db_path)
            code = server.create_auth_code(
                client_id="registered_app",
                redirect_uri="https://example.com/cb",
                code_challenge="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                code_challenge_method="S256",
            )

            # With MCP_OAUTH_STRICT_CLIENT=1, empty client_id is rejected
            with unittest.mock.patch.dict("os.environ", {"MCP_OAUTH_STRICT_CLIENT": "1"}):
                with self.assertRaises(ValueError) as ctx:
                    server.exchange_code_for_token(
                        code=code,
                        client_id="",
                        redirect_uri="https://example.com/cb",
                        code_verifier="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                    )
                self.assertIn("client_id is required", str(ctx.exception))

    def test_unregistered_client_rejected_by_default(self):
        # By default, strict mode is ON: arbitrary client_id + https redirect is rejected
        self.assertFalse(is_uri_allowed_for_client("unregistered_client", "https://evil.example/cb", None))
        self.assertFalse(is_uri_allowed_for_client("", "https://evil.example/cb", None))
        # With opt-out MCP_OAUTH_STRICT_CLIENT=0
        with unittest.mock.patch.dict("os.environ", {"MCP_OAUTH_STRICT_CLIENT": "0"}):
            self.assertTrue(is_uri_allowed_for_client("unregistered_client", "https://evil.example/cb", None))

    def test_plain_pkce_rejection_by_default(self):
        # Plain PKCE rejected by default
        self.assertFalse(verify_pkce("secret_verifier_123456789012345678901234567890", "secret_verifier_123456789012345678901234567890", "plain"))
        # Opt-in plain PKCE allows it
        with unittest.mock.patch.dict("os.environ", {"MCP_OAUTH_ALLOW_PLAIN_PKCE": "1"}):
            self.assertTrue(verify_pkce("secret_verifier_123456789012345678901234567890", "secret_verifier_123456789012345678901234567890", "plain"))

    def test_authorize_endpoint_validations(self):
        import asyncio
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_auth_val.db"
            server = LocalOAuthServer(admin_password="sec", db_path=db_path)

            # 1. Missing client_id -> 400
            req1 = MagicMock(spec=Request)
            req1.method = "GET"
            req1.query_params = {"redirect_uri": "https://chatgpt.com/connector_platform_oauth_redirect", "code_challenge": "abc"}
            req1.client = None
            resp1 = asyncio.run(oauth_authorize_endpoint(req1, server))
            self.assertEqual(resp1.status_code, 400)

            # 2. Missing code_challenge -> 400
            req2 = MagicMock(spec=Request)
            req2.method = "GET"
            req2.query_params = {"client_id": "chatgpt", "redirect_uri": "https://chatgpt.com/connector_platform_oauth_redirect"}
            req2.client = None
            resp2 = asyncio.run(oauth_authorize_endpoint(req2, server))
            self.assertEqual(resp2.status_code, 400)

            # 3. Plain code_challenge_method -> 400 by default
            req3 = MagicMock(spec=Request)
            req3.method = "GET"
            req3.query_params = {
                "client_id": "chatgpt",
                "redirect_uri": "https://chatgpt.com/connector_platform_oauth_redirect",
                "code_challenge": "abc",
                "code_challenge_method": "plain",
            }
            req3.client = None
            resp3 = asyncio.run(oauth_authorize_endpoint(req3, server))
            self.assertEqual(resp3.status_code, 400)

            # 4. Unknown client + arbitrary URI -> 400
            req4 = MagicMock(spec=Request)
            req4.method = "GET"
            req4.query_params = {
                "client_id": "attacker_app",
                "redirect_uri": "https://evil.example/cb",
                "code_challenge": "abc",
                "code_challenge_method": "S256",
            }
            req4.client = None
            resp4 = asyncio.run(oauth_authorize_endpoint(req4, server))
            self.assertEqual(resp4.status_code, 400)

            # 5. Unsupported response_type -> 400
            req5 = MagicMock(spec=Request)
            req5.method = "GET"
            req5.query_params = {
                "client_id": "chatgpt",
                "redirect_uri": "https://chatgpt.com/connector_platform_oauth_redirect",
                "response_type": "token",
                "code_challenge": "abc",
                "code_challenge_method": "S256",
            }
            req5.client = None
            resp5 = asyncio.run(oauth_authorize_endpoint(req5, server))
            self.assertEqual(resp5.status_code, 400)
            self.assertIn("unsupported_response_type", resp5.body.decode("utf-8"))

    def test_token_exchange_mismatch_and_missing_verifier(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_exchange_val.db"
            server = LocalOAuthServer(admin_password="sec", db_path=db_path)
            verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-1234567890"
            digest = hashlib.sha256(verifier.encode("ascii")).digest()
            challenge = base64url_encode(digest)

            code = server.create_auth_code(
                client_id="chatgpt",
                redirect_uri="https://chatgpt.com/connector_platform_oauth_redirect",
                code_challenge=challenge,
                code_challenge_method="S256",
            )

            # 1. Missing verifier -> fails
            with self.assertRaises(ValueError) as ctx:
                server.exchange_code_for_token(
                    code=code,
                    client_id="chatgpt",
                    redirect_uri="https://chatgpt.com/connector_platform_oauth_redirect",
                    code_verifier="",
                )
            self.assertIn("code_verifier is required", str(ctx.exception))

            # 2. Client id mismatch -> fails
            with self.assertRaises(ValueError) as ctx:
                server.exchange_code_for_token(
                    code=code,
                    client_id="other_client",
                    redirect_uri="https://chatgpt.com/connector_platform_oauth_redirect",
                    code_verifier=verifier,
                )
            self.assertIn("client_id mismatch", str(ctx.exception))

            # 3. Redirect URI mismatch -> fails
            with self.assertRaises(ValueError) as ctx:
                server.exchange_code_for_token(
                    code=code,
                    client_id="chatgpt",
                    redirect_uri="https://chatgpt.com/wrong_callback",
                    code_verifier=verifier,
                )
            self.assertIn("redirect_uri mismatch", str(ctx.exception))

            # 4. Valid exchange -> succeeds
            token_res = server.exchange_code_for_token(
                code=code,
                client_id="chatgpt",
                redirect_uri="https://chatgpt.com/connector_platform_oauth_redirect",
                code_verifier=verifier,
            )
            self.assertIn("access_token", token_res)
            self.assertTrue(server.is_token_valid(token_res["access_token"]))


if __name__ == "__main__":
    unittest.main()
