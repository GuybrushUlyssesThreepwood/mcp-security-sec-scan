# Changelog

All notable changes to `mcp-sec-scan` are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/); this project uses semantic versioning.

## [1.0.0] - 2026-08 (planned public release)
### Added
- CLI `mcp-sec-scan <url>` for remote MCP servers (Streamable HTTP).
- 8 checks: TLS enforced, authentication required, unauthenticated tool listing, OAuth 2.1 metadata & PKCE
  (S256), tool-poisoning heuristic, CORS configuration, error verbosity, rate limiting (`--active`).
- Markdown and JSON report export; colored terminal output.
- `--ci` mode with meaningful exit codes (2 = problem, 1 = warn, 0 = clean).
- Reusable GitHub Action (`.github/actions/scan`).
- `--token` / `MCP_SEC_SCAN_TOKEN` for authenticated deep checks.
- Bundled intentionally-vulnerable test server + CI self-test; unit tests.

### Backlog (tracked as issues)
- SARIF output (GitHub Security tab integration).
- Expand from 8 to 12+ checks.
