# Changelog

All notable changes to `mcp-sec-scan` are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/); this project uses semantic versioning.

## [1.1.0] - 2026-07
### Added
- Check: **security headers** — flags missing HSTS (over HTTPS) and `X-Content-Type-Options: nosniff`.
- Check: **origin-header validation** — sends `initialize` with a foreign `Origin` and flags servers that
  accept it, per the MCP Streamable HTTP requirement to validate Origin against DNS-rebinding attacks.
- **SARIF 2.1.0 output** (`--sarif <file>`) for GitHub Code Scanning; the reusable Action emits it by
  default and the README shows the `upload-sarif` step (results land in the Security tab).
- 5 new unit tests; new checks exercised by the bundled vulnerable-server self-test.

### Changed
- Check count 8 → 10; version bumped to 1.1.0.

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
- Expand from 10 to 12+ checks.
