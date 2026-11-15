# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.7.x   | :white_check_mark: |
| 0.6.x   | :white_check_mark: |
| 0.5.x   | :x:                |
| < 0.5.0 | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in `mcp-server-core`, please DO NOT open a public issue.
Instead, report it responsibly via GitHub Private Vulnerability Reporting or by contacting the maintainers directly.

Please include:
- A description of the issue and potential impact
- Reproduction steps or proof of concept
- Your environment details (OS, Python version)

We will respond promptly and coordinate a patch and advisory.

## Security Architecture & Best Practices

`mcp-server-core` implements strict defense-in-depth security controls:
1. **OAuth 2.1 & PKCE**: Only `S256` code challenge method is advertised and permitted by default. Plain PKCE is disabled unless explicitly overridden via `MCP_OAUTH_ALLOW_PLAIN_PKCE=1`.
2. **Redirect URI Validation**: Strictly validated against RFC 6749 / RFC 8252 (loopback addresses or HTTPS only, no URI fragments, length capped). Preset clients such as ChatGPT are restricted to canonical OpenAI callback endpoints.
3. **Tunnel Token Handling**: Cloudflare Tunnel tokens are supplied strictly via environment variables (`TUNNEL_TOKEN`) and never exposed in process argument tables or CLI flags.
4. **Rate Limiting & DCR Protection**: Authentication attempts and dynamic client registrations are strictly rate-limited and bounded in memory to prevent denial-of-service.
5. **Reverse Proxy Trust**: `X-Forwarded-For` and `X-Forwarded-Proto` headers are evaluated only when requests originate from trusted private/loopback reverse proxies.
6. **Automatic Credential & Payload Sanitization**: The logging and observability subsystem automatically redacts authorization tokens, client secrets, API keys, and sensitive payload parameters, capping argument previews before persisting logs to disk or emitting them to console.
