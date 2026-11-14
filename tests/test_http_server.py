import asyncio
import hashlib
import tempfile
import unittest
from pathlib import Path

import httpx
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from mcp.server.fastmcp import FastMCP
from mcp_server_core.env import DeploymentEnvConfig
from mcp_server_core.http_server import (
    HTTPAuthenticationMiddleware,
    NoCacheMiddleware,
    create_mcp_asgi_app,
    get_local_ip,
    mount_mcp_oauth_routes,
)
from mcp_server_core.oauth import LocalOAuthServer, base64url_encode


class TestHttpServerModule(unittest.IsolatedAsyncioTestCase):
    def test_get_local_ip(self):
        ip = get_local_ip()
        self.assertIsInstance(ip, str)
        parts = ip.split(".")
        self.assertEqual(len(parts), 4)

    async def test_no_cache_middleware(self):
        async def dummy_endpoint(request: Request):
            return JSONResponse({"data": "ok"})

        app = Starlette(routes=[Route("/test", dummy_endpoint)])
        app.add_middleware(NoCacheMiddleware)

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            resp = await client.get("/test")
            self.assertEqual(resp.status_code, 200)
            self.assertIn("no-cache", resp.headers.get("Cache-Control", ""))
            self.assertEqual(resp.headers.get("Pragma"), "no-cache")
            self.assertEqual(resp.headers.get("Expires"), "0")

    async def test_http_auth_middleware(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_auth.db"
            oauth_server = LocalOAuthServer(admin_password="sec_valid_key", db_path=db_path)

            async def protected_endpoint(request: Request):
                return JSONResponse({"status": "protected_success"})

            async def public_endpoint(request: Request):
                return JSONResponse({"status": "public_success"})

            app = Starlette(
                routes=[
                    Route("/", public_endpoint),
                    Route("/health", public_endpoint),
                    Route("/mcp/.well-known/oauth-protected-resource", public_endpoint),
                    Route("/api/data", protected_endpoint, methods=["GET", "OPTIONS"]),
                ]
            )
            app.add_middleware(
                HTTPAuthenticationMiddleware,
                oauth_server=oauth_server,
                require_auth=True,
                allow_query_auth=True,
                enable_public_oauth=True,
            )
            app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://testserver"
            ) as client:
                # 1. OPTIONS preflight
                options_resp = await client.options("/api/data")
                self.assertEqual(options_resp.status_code, 200)

                # 2. Public endpoints bypass auth
                resp_root = await client.get("/")
                self.assertEqual(resp_root.status_code, 200)

                resp_health = await client.get("/health")
                self.assertEqual(resp_health.status_code, 200)

                resp_wellknown = await client.get("/mcp/.well-known/oauth-protected-resource")
                self.assertEqual(resp_wellknown.status_code, 200)

                # 3. Protected endpoint without token -> 401
                resp_no_token = await client.get("/api/data")
                self.assertEqual(resp_no_token.status_code, 401)
                self.assertIn("WWW-Authenticate", resp_no_token.headers)

                # 4. Protected endpoint with invalid token -> 403
                resp_bad_token = await client.get(
                    "/api/data", headers={"Authorization": "Bearer invalid_key"}
                )
                self.assertEqual(resp_bad_token.status_code, 403)

                # 5. Protected endpoint with valid Bearer token -> 200
                resp_good_token = await client.get(
                    "/api/data", headers={"Authorization": "Bearer sec_valid_key"}
                )
                self.assertEqual(resp_good_token.status_code, 200)
                self.assertEqual(resp_good_token.json()["status"], "protected_success")

                # 6. Protected endpoint with query token when allow_query_auth=True -> 200
                resp_query_token = await client.get("/api/data?token=sec_valid_key")
                self.assertEqual(resp_query_token.status_code, 200)

    async def test_oauth_routes_and_flow(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_oauth_flow.db"
            oauth_server = LocalOAuthServer(admin_password="sec_super_secret_key", db_path=db_path)
            env_cfg = DeploymentEnvConfig(
                port=8788,
                require_auth=True,
                api_key="sec_super_secret_key",
                enable_public_oauth=True,
            )

            server = FastMCP("TestFlowServer")
            mount_mcp_oauth_routes(
                server=server,
                oauth_server=oauth_server,
                service_name="test_service",
                enable_public_oauth=True,
            )
            app = create_mcp_asgi_app(
                server=server,
                env_cfg=env_cfg,
                oauth_server=oauth_server,
                require_auth=True,
            )

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://testserver"
            ) as client:
                # 1. Health check
                health_resp = await client.get("/health")
                self.assertEqual(health_resp.status_code, 200)
                self.assertEqual(health_resp.json()["status"], "healthy")

                # 2. RFC 9728 Protected Resource Metadata
                meta_resp = await client.get("/.well-known/oauth-protected-resource")
                self.assertEqual(meta_resp.status_code, 200)
                data = meta_resp.json()
                self.assertIn("resource", data)
                self.assertIn("authorization_servers", data)

                # 3. RFC 8414 Authorization Server Metadata
                server_meta_resp = await client.get("/.well-known/oauth-authorization-server")
                self.assertEqual(server_meta_resp.status_code, 200)
                as_data = server_meta_resp.json()
                self.assertIn("authorization_endpoint", as_data)
                self.assertIn("token_endpoint", as_data)

                # 4. RFC 7591 Dynamic Client Registration
                reg_resp = await client.post(
                    "/oauth/register",
                    json={"client_name": "Test Client", "redirect_uris": ["https://example.com/callback"]},
                )
                self.assertEqual(reg_resp.status_code, 201)
                reg_data = reg_resp.json()
                client_id = reg_data["client_id"]

                # 5. OAuth Authorize Page - GET
                code_verifier = "a" * 50
                digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
                code_challenge = base64url_encode(digest)

                auth_get = await client.get(
                    f"/oauth/authorize?client_id={client_id}&redirect_uri=https://example.com/callback&code_challenge={code_challenge}&code_challenge_method=S256"
                )
                self.assertEqual(auth_get.status_code, 200)
                self.assertIn("安全授权", auth_get.text)

                # 6. OAuth Authorize - POST with invalid password -> 401
                auth_fail = await client.post(
                    "/oauth/authorize",
                    data={
                        "client_id": client_id,
                        "redirect_uri": "https://example.com/callback",
                        "code_challenge": code_challenge,
                        "code_challenge_method": "S256",
                        "password": "wrong",
                    },
                )
                self.assertEqual(auth_fail.status_code, 401)

                # 7. OAuth Authorize - POST with correct password -> 302 Redirect
                auth_post = await client.post(
                    "/oauth/authorize",
                    data={
                        "client_id": client_id,
                        "redirect_uri": "https://example.com/callback",
                        "code_challenge": code_challenge,
                        "code_challenge_method": "S256",
                        "password": "sec_super_secret_key",
                        "state": "random_state_123",
                    },
                )
                self.assertEqual(auth_post.status_code, 302)
                location = auth_post.headers["Location"]
                self.assertIn("code=auth_code_", location)
                self.assertIn("state=random_state_123", location)

                # Extract code from callback redirect
                from urllib.parse import parse_qs, urlparse
                qs = parse_qs(urlparse(location).query)
                code = qs["code"][0]

                # 8. Token Exchange at /oauth/token
                token_resp = await client.post(
                    "/oauth/token",
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "client_id": client_id,
                        "redirect_uri": "https://example.com/callback",
                        "code_verifier": code_verifier,
                    },
                )
                self.assertEqual(token_resp.status_code, 200)
                token_data = token_resp.json()
                self.assertIn("access_token", token_data)
                self.assertEqual(token_data["token_type"], "Bearer")

                # 9. Verify token validity on OAuth server
                self.assertTrue(oauth_server.is_token_valid(token_data["access_token"]))

    async def test_oauth_disabled_endpoints(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_oauth_disabled.db"
            oauth_server = LocalOAuthServer(admin_password="sec_test", db_path=db_path)
            env_cfg = DeploymentEnvConfig(
                port=8788,
                require_auth=True,
                api_key="sec_test",
                enable_public_oauth=False,
            )

            server = FastMCP("DisabledOAuthServer")
            mount_mcp_oauth_routes(
                server=server,
                oauth_server=oauth_server,
                service_name="disabled_service",
                enable_public_oauth=False,
            )
            app = create_mcp_asgi_app(
                server=server,
                env_cfg=env_cfg,
                oauth_server=oauth_server,
                require_auth=True,
            )

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://testserver"
            ) as client:
                # 1. Protected resource metadata disabled -> 404
                resp1 = await client.get("/.well-known/oauth-protected-resource")
                self.assertEqual(resp1.status_code, 404)
                self.assertEqual(resp1.json()["error"], "oauth_disabled")

                # 2. Authorization server metadata disabled -> 404
                resp2 = await client.get("/.well-known/oauth-authorization-server")
                self.assertEqual(resp2.status_code, 404)
                self.assertEqual(resp2.json()["error"], "oauth_disabled")

                # 3. Register disabled -> 403
                resp3 = await client.post("/oauth/register", json={})
                self.assertEqual(resp3.status_code, 403)
                self.assertEqual(resp3.json()["error"], "registration_disabled")

                # 4. Authorize disabled -> 403
                resp4 = await client.get("/oauth/authorize")
                self.assertEqual(resp4.status_code, 403)
                self.assertEqual(resp4.json()["error"], "authorization_disabled")

                # 5. Token disabled -> 403
                resp5 = await client.post("/oauth/token")
                self.assertEqual(resp5.status_code, 403)
                self.assertEqual(resp5.json()["error"], "token_endpoint_disabled")

                # 6. Protected resource without token has error message for disabled public oauth
                resp6 = await client.get("/mcp")
                self.assertEqual(resp6.status_code, 401)
                self.assertIn("Direct public access to this backend is disabled", resp6.json()["message"])

    async def test_root_info_and_jwks(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_root.db"
            oauth_server = LocalOAuthServer(admin_password="sec_test", db_path=db_path)
            env_cfg = DeploymentEnvConfig(port=8788, require_auth=False)

            # With custom builder
            def custom_builder(req):
                return {"custom_key": "custom_value"}

            server = FastMCP("RootInfoServer")
            mount_mcp_oauth_routes(
                server=server,
                oauth_server=oauth_server,
                service_name="custom_service",
                root_info_builder=custom_builder,
            )
            app = create_mcp_asgi_app(server=server, env_cfg=env_cfg, oauth_server=oauth_server)

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://testserver"
            ) as client:
                root_resp = await client.get("/")
                self.assertEqual(root_resp.status_code, 200)
                self.assertEqual(root_resp.json()["custom_key"], "custom_value")

                jwks_resp = await client.get("/oauth/jwks.json")
                self.assertEqual(jwks_resp.status_code, 200)
                self.assertEqual(jwks_resp.json(), {"keys": []})

    async def test_token_endpoint_errors_and_basic_auth(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_tok_err.db"
            oauth_server = LocalOAuthServer(admin_password="sec_test", db_path=db_path)
            env_cfg = DeploymentEnvConfig(port=8788, enable_public_oauth=True)

            server = FastMCP("TokErrServer")
            mount_mcp_oauth_routes(server=server, oauth_server=oauth_server, enable_public_oauth=True)
            app = create_mcp_asgi_app(server=server, env_cfg=env_cfg, oauth_server=oauth_server)

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://testserver"
            ) as client:
                # Unsupported grant type
                resp1 = await client.post(
                    "/oauth/token",
                    data={"grant_type": "client_credentials"},
                )
                self.assertEqual(resp1.status_code, 400)
                self.assertEqual(resp1.json()["error"], "unsupported_grant_type")

                # Basic auth header extraction
                import base64
                basic = base64.b64encode(b"my_basic_client:secret").decode("utf-8")
                resp2 = await client.post(
                    "/oauth/token",
                    headers={"Authorization": f"Basic {basic}"},
                    data={"grant_type": "authorization_code", "code": "fake_code"},
                )
                self.assertEqual(resp2.status_code, 400)
                self.assertEqual(resp2.json()["error"], "invalid_grant")

    async def test_custom_service_title_and_consent_renderer(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_title_render.db"
            oauth_server = LocalOAuthServer(admin_password="sec_test", db_path=db_path)
            env_cfg = DeploymentEnvConfig(port=8788, enable_public_oauth=True)

            # 1. Custom service_title
            server1 = FastMCP("TitleServer")
            mount_mcp_oauth_routes(
                server=server1,
                oauth_server=oauth_server,
                service_name="enterprise_core",
                service_title="Enterprise MCP Gateway",
            )
            app1 = create_mcp_asgi_app(server=server1, env_cfg=env_cfg, oauth_server=oauth_server)

            reg1 = oauth_server.register_client({"client_name": "App 1", "redirect_uris": ["https://example.com/cb"]})
            cid1 = reg1["client_id"]
            code_verifier = "a" * 50
            digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
            challenge = base64url_encode(digest)

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app1), base_url="http://testserver"
            ) as client:
                res1 = await client.get(f"/oauth/authorize?client_id={cid1}&redirect_uri=https://example.com/cb&code_challenge={challenge}")
                self.assertEqual(res1.status_code, 200)
                self.assertIn("Enterprise MCP Gateway", res1.text)
                self.assertNotIn("ChatGPT", res1.text)

            # 2. Custom consent renderer callback
            server2 = FastMCP("CustomRendererServer")
            def my_renderer(err, cid, ruri, sc, st, cc, cm, service_title=""):
                return f"<html><body>Custom Page for {service_title} CID={cid}</body></html>"

            mount_mcp_oauth_routes(
                server=server2,
                oauth_server=oauth_server,
                service_title="Branded Server",
                custom_consent_renderer=my_renderer,
            )
            app2 = create_mcp_asgi_app(server=server2, env_cfg=env_cfg, oauth_server=oauth_server)

            reg2 = oauth_server.register_client({"client_name": "App 2", "redirect_uris": ["https://example.com/cb"]})
            cid2 = reg2["client_id"]
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app2), base_url="http://testserver"
            ) as client:
                res2 = await client.get(f"/oauth/authorize?client_id={cid2}&redirect_uri=https://example.com/cb&code_challenge={challenge}")
                self.assertEqual(res2.status_code, 200)
                self.assertIn(f"Custom Page for Branded Server CID={cid2}", res2.text)

    async def test_custom_scopes_and_dict_consent_renderer(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test_scopes.db"
            oauth_server = LocalOAuthServer(admin_password="sec_test", db_path=db_path)
            
            # Test set_consent_template_renderer with single dict argument
            def my_dict_renderer(ctx: dict) -> str:
                return f"<html><body><h1>Dict Renderer for {ctx['service_title']}</h1><p>Scope={ctx['scope']}</p></body></html>"

            oauth_server.set_consent_template_renderer(my_dict_renderer)
            env_cfg = DeploymentEnvConfig(port=8788, enable_public_oauth=True)

            server = FastMCP("ScopesServer")
            mount_mcp_oauth_routes(
                server=server,
                oauth_server=oauth_server,
                service_name="finance_mcp",
                service_title="财务报表 MCP 核心中台",
                custom_scopes=["data:read", "report:export"],
            )
            app = create_mcp_asgi_app(server=server, env_cfg=env_cfg, oauth_server=oauth_server)

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://testserver"
            ) as client:
                # 1. Check consent page rendered via dict callback for registered client
                reg_info = oauth_server.register_client({"client_name": "Test Client", "redirect_uris": ["https://cb.com/callback"]})
                cid = reg_info["client_id"]
                res_auth = await client.get(
                    f"/oauth/authorize?client_id={cid}&scope=data:read&redirect_uri=https://cb.com/callback&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
                )
                self.assertEqual(res_auth.status_code, 200)
                self.assertIn("Dict Renderer for 财务报表 MCP 核心中台", res_auth.text)
                self.assertIn("Scope=data:read", res_auth.text)

                # 2. Check RFC 9728 scopes
                res_res = await client.get("/.well-known/oauth-protected-resource")
                self.assertEqual(res_res.status_code, 200)
                self.assertEqual(res_res.json()["scopes_supported"], ["data:read", "report:export"])

                # 3. Check RFC 8414 scopes
                res_meta = await client.get("/.well-known/oauth-authorization-server")
                self.assertEqual(res_meta.status_code, 200)
                self.assertEqual(res_meta.json()["scopes_supported"], ["data:read", "report:export"])

    async def test_sse_streaming_response(self):
        from starlette.responses import StreamingResponse

        async def numbers_stream():
            for i in range(3):
                yield f"data: message {i}\n\n"
                await asyncio.sleep(0.01)

        async def sse_endpoint(request: Request):
            return StreamingResponse(
                numbers_stream(),
                media_type="text/event-stream",
            )

        app = Starlette(routes=[Route("/events", sse_endpoint)])
        app.add_middleware(NoCacheMiddleware)
        app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

        # 1. High-level client test
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            async with client.stream("GET", "/events") as resp:
                self.assertEqual(resp.status_code, 200)
                self.assertIn("text/event-stream", resp.headers["content-type"])
                self.assertIn("no-cache", resp.headers.get("cache-control", ""))
                body = "".join([chunk async for chunk in resp.aiter_text()])
                self.assertIn("data: message 0", body)
                self.assertIn("data: message 1", body)
                self.assertIn("data: message 2", body)

        # 2. Low-level ASGI incremental chunk test (proving zero middleware buffering)
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "path": "/events",
            "raw_path": b"/events",
            "query_string": b"",
            "headers": [],
        }
        req_sent = False
        stream_done = asyncio.Event()

        async def receive():
            nonlocal req_sent
            if not req_sent:
                req_sent = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await stream_done.wait()
            return {"type": "http.disconnect"}

        messages = []

        async def send(msg):
            messages.append(msg)
            if msg.get("type") == "http.response.body" and not msg.get("more_body", False):
                stream_done.set()

        await app(scope, receive, send)

        body_messages = [m for m in messages if m["type"] == "http.response.body" and m.get("body")]
        self.assertGreaterEqual(len(body_messages), 3)
        self.assertEqual(
            [m["body"].decode("utf-8").strip() for m in body_messages],
            ["data: message 0", "data: message 1", "data: message 2"],
        )


if __name__ == "__main__":
    unittest.main()
