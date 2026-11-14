import os
import tempfile
import unittest
from pathlib import Path

from mcp_server_core.env import (
    DEFAULT_GLOBAL_ENV_FILE,
    DEFAULT_GLOBAL_MCP_DIR,
    DEFAULT_MCP_PORT,
    DEFAULT_OAUTH_SCOPES,
    DeploymentEnvConfig,
    _parse_bool,
    _parse_int,
    get_global_env_file,
    get_global_mcp_dir,
    get_runtime_dir,
    parse_env_file,
    update_env_variable,
    update_global_env_variable,
)
from mcp_server_core.metadata import ServiceMetadata


class TestEnvModule(unittest.TestCase):
    def test_parse_bool(self):
        self.assertTrue(_parse_bool("true"))
        self.assertTrue(_parse_bool("TRUE"))
        self.assertTrue(_parse_bool("1"))
        self.assertTrue(_parse_bool("yes"))
        self.assertTrue(_parse_bool("on"))
        self.assertTrue(_parse_bool("y"))
        self.assertTrue(_parse_bool(True))

        self.assertFalse(_parse_bool("false"))
        self.assertFalse(_parse_bool("0"))
        self.assertFalse(_parse_bool("no"))
        self.assertFalse(_parse_bool("off"))
        self.assertFalse(_parse_bool(""))
        self.assertFalse(_parse_bool(False))

        # Defaults on unknown
        self.assertTrue(_parse_bool(None, default=True))
        self.assertFalse(_parse_bool(None, default=False))
        self.assertTrue(_parse_bool("unknown", default=True))
        self.assertFalse(_parse_bool("unknown", default=False))

    def test_parse_int(self):
        self.assertEqual(_parse_int("9000"), 9000)
        self.assertEqual(_parse_int(8888), 8888)
        self.assertEqual(_parse_int("invalid", default=8788), 8788)
        self.assertEqual(_parse_int("", default=8788), 8788)
        self.assertEqual(_parse_int(None, default=8788), 8788)

    def test_get_runtime_dir(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            # Default directory
            rdir = get_runtime_dir(base)
            self.assertTrue(rdir.exists())
            self.assertEqual(rdir, base / ".runtime")

            # Custom env var
            old_val = os.environ.get("MCP_RUNTIME_DIR")
            try:
                os.environ["MCP_RUNTIME_DIR"] = ".custom_runtime"
                rdir_custom = get_runtime_dir(base)
                self.assertTrue(rdir_custom.exists())
                self.assertEqual(rdir_custom, base / ".custom_runtime")
            finally:
                if old_val is not None:
                    os.environ["MCP_RUNTIME_DIR"] = old_val
                else:
                    os.environ.pop("MCP_RUNTIME_DIR", None)

    def test_update_env_variable(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            env_file = Path(tmp_dir) / ".env"
            # 1. Create new variable in non-existing file (does not pollute os.environ)
            old_val = os.environ.get("TEST_KEY")
            update_env_variable("TEST_KEY", "first_value", env_file)
            self.assertEqual(os.environ.get("TEST_KEY"), old_val)
            content = env_file.read_text(encoding="utf-8")
            self.assertIn("TEST_KEY=first_value", content)

            # 2. Update existing variable
            update_env_variable("TEST_KEY", "second_value", env_file)
            self.assertEqual(os.environ.get("TEST_KEY"), old_val)
            content = env_file.read_text(encoding="utf-8")
            self.assertIn("TEST_KEY=second_value", content)
            self.assertNotIn("TEST_KEY=first_value", content)

            # 3. Update export-style variable
            env_file.write_text("export EXPORTED_KEY=old_val\nOTHER=keep_me\n", encoding="utf-8")
            update_env_variable("EXPORTED_KEY", "new_val", env_file)
            content = env_file.read_text(encoding="utf-8")
            self.assertIn("EXPORTED_KEY=new_val", content)
            self.assertIn("OTHER=keep_me", content)

    def test_deployment_env_config_defaults(self):
        cfg = DeploymentEnvConfig()
        self.assertTrue(cfg.enabled)
        self.assertEqual(cfg.host, "127.0.0.1")
        self.assertEqual(cfg.port, 8788)
        self.assertEqual(cfg.path, "/mcp")
        self.assertTrue(cfg.require_auth)
        self.assertTrue(cfg.tunnel)

    def test_deployment_env_config_load_and_overrides(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            env_file = base / ".env"
            env_file.write_text(
                "MCP_PORT=9999\n"
                "MCP_HOST=0.0.0.0\n"
                "MCP_REQUIRE_AUTH=false\n"
                "MCP_API_KEY=test_custom_key\n"
                "MCP_TUNNEL=false\n"
                "MCP_ALLOW_QUERY_AUTH=true\n"
                "MCP_ENABLE_PUBLIC_OAUTH=true\n",
                encoding="utf-8",
            )

            cfg = DeploymentEnvConfig.load(base)
            self.assertEqual(cfg.port, 9999)
            self.assertEqual(cfg.host, "0.0.0.0")
            self.assertFalse(cfg.require_auth)
            self.assertEqual(cfg.api_key, "test_custom_key")
            self.assertFalse(cfg.tunnel)
            self.assertTrue(cfg.allow_query_auth)
            self.assertTrue(cfg.enable_public_oauth)

            # Test explicit overrides dict
            cfg_overridden = DeploymentEnvConfig.load(
                base, overrides={"port": 1234, "require_auth": True}
            )
            self.assertEqual(cfg_overridden.port, 1234)
            self.assertTrue(cfg_overridden.require_auth)

    def test_deployment_env_config_auto_generates_api_key(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            env_file = base / ".env"
            env_file.write_text("MCP_REQUIRE_AUTH=true\nMCP_API_KEY=\n", encoding="utf-8")

            # Clean any environment contamination
            old_key = os.environ.pop("MCP_API_KEY", None)
            try:
                # 1. Pure load should NOT generate or write key
                pure_cfg = DeploymentEnvConfig.load(base)
                self.assertEqual(pure_cfg.api_key, "")
                self.assertEqual(env_file.read_text(encoding="utf-8"), "MCP_REQUIRE_AUTH=true\nMCP_API_KEY=\n")

                # 2. Explicit auto_create_key=True generates and persists key
                cfg = DeploymentEnvConfig.load(base, auto_create_key=True)
                self.assertTrue(cfg.api_key.startswith("sec_"))
                self.assertGreater(len(cfg.api_key), 10)
                # Verify persisted to .env
                content = env_file.read_text(encoding="utf-8")
                self.assertIn(f"MCP_API_KEY={cfg.api_key}", content)
            finally:
                if old_key is not None:
                    os.environ["MCP_API_KEY"] = old_key
                else:
                    os.environ.pop("MCP_API_KEY", None)

    def test_service_metadata(self):
        # Default metadata
        meta = ServiceMetadata(service_name="analytics_mcp")
        self.assertEqual(meta.service_name, "analytics_mcp")
        self.assertEqual(meta.service_title, "Analytics Mcp")
        self.assertEqual(meta.local_port, 8788)
        self.assertEqual(meta.supported_scopes, DEFAULT_OAUTH_SCOPES)
        ua = meta.get_user_agent()
        self.assertIn("analytics_mcp/1.0", ua)
        self.assertIn("mcp-server-core/", ua)

        # Custom metadata
        custom_meta = ServiceMetadata(
            service_name="finance_mcp",
            service_title="Finance Central Hub",
            local_port=9010,
            supported_scopes=["data:read", "data:write"],
            user_agent="CustomAgent/2.0",
        )
        self.assertEqual(custom_meta.service_title, "Finance Central Hub")
        self.assertEqual(custom_meta.get_user_agent(), "CustomAgent/2.0")
        d = custom_meta.to_dict()
        self.assertEqual(d["local_port"], 9010)
        self.assertEqual(d["supported_scopes"], ["data:read", "data:write"])

    def test_extended_env_configurations(self):
        self.assertEqual(DEFAULT_MCP_PORT, 8788)
        self.assertIn("mcp:read", DEFAULT_OAUTH_SCOPES)

        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            (base / ".env").write_text(
                "MCP_OAUTH_ISSUER=https://auth.company.internal\n"
                "MCP_OAUTH_SCOPES=custom:read,custom:write,audit:log\n"
                "MCP_AUTH_MAX_ATTEMPTS=8\n"
                "MCP_AUTH_LOCKOUT_SECS=1200\n"
                "CLOUDFLARE_METRICS_PORT=20246\n",
                encoding="utf-8",
            )
            try:
                cfg = DeploymentEnvConfig.load(base)
                self.assertEqual(cfg.oauth_issuer, "https://auth.company.internal")
                self.assertEqual(cfg.oauth_scopes, ["custom:read", "custom:write", "audit:log"])
                self.assertEqual(cfg.auth_max_attempts, 8)
                self.assertEqual(cfg.auth_lockout_secs, 1200)
                self.assertEqual(cfg.cloudflare_metrics_port, 20246)
            finally:
                for k in ["MCP_OAUTH_ISSUER", "MCP_OAUTH_SCOPES", "MCP_AUTH_MAX_ATTEMPTS", "MCP_AUTH_LOCKOUT_SECS", "CLOUDFLARE_METRICS_PORT"]:
                    os.environ.pop(k, None)


    def test_load_isolation_multi_project(self):
        """Verify sequential loads for different projects in the same process do not leak env vars."""
        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            dir_a = Path(tmp_a)
            dir_b = Path(tmp_b)

            (dir_a / ".env").write_text(
                "MCP_PORT=8081\n"
                "MCP_API_KEY=key_project_a\n"
                "MCP_OAUTH_ISSUER=https://auth-a.example.com\n"
                "MCP_SERVICE_NAME=service_a\n",
                encoding="utf-8",
            )

            (dir_b / ".env").write_text(
                "MCP_PORT=8082\n"
                "MCP_SERVICE_NAME=service_b\n",
                encoding="utf-8",
            )

            # Load project A
            cfg_a = DeploymentEnvConfig.load(dir_a)
            self.assertEqual(cfg_a.port, 8081)
            self.assertEqual(cfg_a.api_key, "key_project_a")
            self.assertEqual(cfg_a.oauth_issuer, "https://auth-a.example.com")
            self.assertEqual(cfg_a.service_name, "service_a")

            # Ensure os.environ was NOT polluted by project A
            self.assertNotEqual(os.environ.get("MCP_PORT"), "8081")
            self.assertNotEqual(os.environ.get("MCP_API_KEY"), "key_project_a")
            self.assertNotEqual(os.environ.get("MCP_OAUTH_ISSUER"), "https://auth-a.example.com")

            # Load project B in the same Python process
            cfg_b = DeploymentEnvConfig.load(dir_b)
            self.assertEqual(cfg_b.port, 8082)
            self.assertEqual(cfg_b.api_key, "")  # Clean, no inheritance from project A!
            self.assertEqual(cfg_b.oauth_issuer, "")  # Clean, no inheritance from project A!
            self.assertEqual(cfg_b.service_name, "service_b")

    def test_cors_origins_config(self):
        # Default is ["*"]
        cfg_def = DeploymentEnvConfig()
        self.assertEqual(cfg_def.cors_origins, ["*"])

        # From .env comma-separated string
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            (base / ".env").write_text(
                "MCP_CORS_ORIGINS=https://chatgpt.com, https://claude.ai\n",
                encoding="utf-8",
            )
            cfg = DeploymentEnvConfig.load(base)
            self.assertEqual(cfg.cors_origins, ["https://chatgpt.com", "https://claude.ai"])

        # Overrides list
        cfg_ovr = DeploymentEnvConfig.load(base, overrides={"cors_origins": ["https://custom.app"]})
        self.assertEqual(cfg_ovr.cors_origins, ["https://custom.app"])

    def test_env_config_all_security_and_runtime_variables(self):
        """Verify .env declarations for all security/runtime variables flow into config and consumers."""
        from mcp_server_core.oauth import (
            LocalOAuthServer,
            get_allowed_redirect_uris,
            is_trusted_proxy,
            is_uri_allowed_for_client,
            verify_pkce,
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            (base / ".env").write_text(
                "MCP_ALLOWED_REDIRECT_URIS=https://custom.example/cb,https://custom2.example/cb\n"
                "MCP_TRUST_PROXY_HEADERS=1\n"
                "MCP_OAUTH_STRICT_CLIENT=0\n"
                "MCP_OAUTH_ALLOW_PLAIN_PKCE=1\n"
                "MCP_OAUTH_REQUIRE_PKCE=0\n"
                "MCP_PRESET_CLIENT_ID=claude_agent\n"
                "MCP_PRESET_CLIENT_NAME=Claude Agent\n"
                "MCP_RUNTIME_DIR=.custom_runtime_test\n",
                encoding="utf-8",
            )
            cfg = DeploymentEnvConfig.load(base)
            self.assertEqual(cfg.allowed_redirect_uris, ["https://custom.example/cb", "https://custom2.example/cb"])
            self.assertTrue(cfg.trust_proxy_headers)
            self.assertFalse(cfg.oauth_strict_client)
            self.assertTrue(cfg.oauth_allow_plain_pkce)
            self.assertFalse(cfg.oauth_require_pkce)
            self.assertEqual(cfg.preset_client_id, "claude_agent")
            self.assertEqual(cfg.preset_client_name, "Claude Agent")
            self.assertEqual(cfg.runtime_dir, ".custom_runtime_test")

            # Verify LocalOAuthServer initialized with config
            server = LocalOAuthServer(admin_password="sec_pass", db_path=base / "oauth.db", config=cfg)
            self.assertEqual(server.allowed_redirect_uris, ["https://custom.example/cb", "https://custom2.example/cb"])
            self.assertTrue(server.trust_proxy_headers)
            self.assertTrue(server.is_trusted_proxy("8.8.8.8"))
            self.assertTrue(server.is_uri_allowed_for_client("unregistered", "https://evil.example/cb"))
            self.assertTrue(server.verify_pkce("test_verifier", "test_verifier", "plain"))
            self.assertEqual(server.preset_client_id, "claude_agent")
            self.assertEqual(server.preset_client_name, "Claude Agent")
            self.assertTrue(server.is_uri_allowed_for_client("claude_agent", "https://custom.example/cb"))

            # Verify helpers when passed env_cfg
            self.assertEqual(get_allowed_redirect_uris(env_cfg=cfg), ["https://custom.example/cb", "https://custom2.example/cb"])
            self.assertTrue(is_trusted_proxy("8.8.8.8", env_cfg=cfg))
            self.assertTrue(is_uri_allowed_for_client("unregistered", "https://evil.example/cb", env_cfg=cfg))
            self.assertTrue(verify_pkce("v", "v", "plain", env_cfg=cfg))

    def test_global_mcp_env_helpers(self):
        """Test helpers for global ~/.mcp/.env directory, paths, parsing and updating."""
        # 1. Defaults
        self.assertEqual(DEFAULT_GLOBAL_MCP_DIR, Path.home() / ".mcp")
        self.assertEqual(DEFAULT_GLOBAL_ENV_FILE, Path.home() / ".mcp" / ".env")
        self.assertEqual(get_global_mcp_dir(), Path.home() / ".mcp")
        self.assertEqual(get_global_env_file(), Path.home() / ".mcp" / ".env")

        # 2. Custom environment overrides
        with tempfile.TemporaryDirectory() as tmp_dir:
            custom_dir = Path(tmp_dir) / "custom_mcp"
            old_dir = os.environ.get("MCP_GLOBAL_DIR")
            old_env = os.environ.get("MCP_GLOBAL_ENV")
            try:
                os.environ["MCP_GLOBAL_DIR"] = str(custom_dir)
                self.assertEqual(get_global_mcp_dir(), custom_dir.resolve())
                self.assertEqual(get_global_env_file(), (custom_dir / ".env").resolve())

                custom_env_file = Path(tmp_dir) / "special.env"
                os.environ["MCP_GLOBAL_ENV"] = str(custom_env_file)
                self.assertEqual(get_global_env_file(), custom_env_file.resolve())

                # Test update_global_env_variable
                update_global_env_variable("GLOBAL_TUNNEL_TOKEN", "eyJh_test_global")
                self.assertTrue(custom_env_file.exists())
                vals = parse_env_file(custom_env_file)
                self.assertEqual(vals.get("GLOBAL_TUNNEL_TOKEN"), "eyJh_test_global")
            finally:
                if old_dir is not None:
                    os.environ["MCP_GLOBAL_DIR"] = old_dir
                else:
                    os.environ.pop("MCP_GLOBAL_DIR", None)
                if old_env is not None:
                    os.environ["MCP_GLOBAL_ENV"] = old_env
                else:
                    os.environ.pop("MCP_GLOBAL_ENV", None)

    def test_deployment_env_config_global_fallback(self):
        """Verify DeploymentEnvConfig seamlessly falls back to ~/.mcp/.env when project .env has empty placeholder or missing keys."""
        with tempfile.TemporaryDirectory() as tmp_global_dir, tempfile.TemporaryDirectory() as tmp_proj_dir:
            global_env = Path(tmp_global_dir) / ".env"
            global_env.write_text(
                "CLOUDFLARE_TUNNEL_TOKEN=global_token_xyz_999\n"
                "CLOUDFLARED_PATH=/opt/cloudflared\n"
                "CLOUDFLARE_METRICS_PORT=20288\n"
                "MCP_UPSTREAM_URL=https://shared.example.com\n",
                encoding="utf-8",
            )

            # Project .env has empty placeholders (scaffolded defaults)
            proj_dir = Path(tmp_proj_dir)
            proj_env = proj_dir / ".env"
            proj_env.write_text(
                "MCP_PORT=8795\n"
                "MCP_REQUIRE_AUTH=true\n"
                "MCP_API_KEY=sec_project_local_key\n"
                "CLOUDFLARE_TUNNEL_TOKEN=\n"  # Empty placeholder in project
                "CLOUDFLARED_PATH=\n"          # Empty placeholder in project
                "MCP_UPSTREAM_URL=\n",         # Empty placeholder in project
                encoding="utf-8",
            )

            cfg = DeploymentEnvConfig.load(proj_dir, global_env_file=global_env)

            # Project-specific fields take project values
            self.assertEqual(cfg.port, 8795)
            self.assertEqual(cfg.api_key, "sec_project_local_key")

            # Empty placeholders fall back to global ~/.mcp/.env
            self.assertEqual(cfg.tunnel_token, "global_token_xyz_999")
            self.assertEqual(cfg.cloudflared_path, "/opt/cloudflared")
            self.assertEqual(cfg.cloudflare_metrics_port, 20288)
            self.assertEqual(cfg.upstream_url, "https://shared.example.com")

    def test_deployment_env_config_precedence_hierarchy(self):
        """Verify strict precedence: overrides > project non-empty > os.environ > global ~/.mcp/.env."""
        with tempfile.TemporaryDirectory() as tmp_global_dir, tempfile.TemporaryDirectory() as tmp_proj_dir:
            global_env = Path(tmp_global_dir) / ".env"
            global_env.write_text(
                "CLOUDFLARE_TUNNEL_TOKEN=from_global_env\n"
                "MCP_PORT=8801\n"
                "MCP_HOST=10.0.0.1\n",
                encoding="utf-8",
            )

            proj_dir = Path(tmp_proj_dir)
            proj_env = proj_dir / ".env"
            proj_env.write_text(
                "MCP_PORT=8802\n"  # Explicit in project
                "CLOUDFLARE_TUNNEL_TOKEN=\n",  # Empty in project
                encoding="utf-8",
            )

            # 1. Project port (8802) overrides global port (8801); global token is used because project token is empty
            cfg = DeploymentEnvConfig.load(proj_dir, global_env_file=global_env)
            self.assertEqual(cfg.port, 8802)
            self.assertEqual(cfg.tunnel_token, "from_global_env")
            self.assertEqual(cfg.host, "10.0.0.1")

            # 2. os.environ overrides global .env, but does NOT override non-empty project .env
            old_port = os.environ.get("MCP_PORT")
            old_token = os.environ.get("CLOUDFLARE_TUNNEL_TOKEN")
            try:
                os.environ["MCP_PORT"] = "8899"
                os.environ["CLOUDFLARE_TUNNEL_TOKEN"] = "from_os_environ"

                cfg2 = DeploymentEnvConfig.load(proj_dir, global_env_file=global_env)
                # Project .env non-empty wins over os.environ
                self.assertEqual(cfg2.port, 8802)
                # os.environ wins over global .env for the empty project placeholder
                self.assertEqual(cfg2.tunnel_token, "from_os_environ")

                # 3. Explicit overrides parameter wins over everything
                cfg3 = DeploymentEnvConfig.load(
                    proj_dir,
                    overrides={"port": 9999, "tunnel_token": "from_overrides"},
                    global_env_file=global_env,
                )
                self.assertEqual(cfg3.port, 9999)
                self.assertEqual(cfg3.tunnel_token, "from_overrides")
            finally:
                if old_port is not None:
                    os.environ["MCP_PORT"] = old_port
                else:
                    os.environ.pop("MCP_PORT", None)
                if old_token is not None:
                    os.environ["CLOUDFLARE_TUNNEL_TOKEN"] = old_token
                else:
                    os.environ.pop("CLOUDFLARE_TUNNEL_TOKEN", None)


if __name__ == "__main__":
    unittest.main()
