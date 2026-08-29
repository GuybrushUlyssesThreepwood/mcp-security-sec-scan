# Changelog

All notable changes to `mcp-sec-scan` are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/); this project uses semantic versioning.

## [Unreleased]
### Added
- **`--passive` observation mode.** Runs only checks that never touch the MCP endpoint itself:
  URL/TLS inspection plus `GET` on the standardised `.well-known` discovery paths (RFC 8414 /
  RFC 9728), which exist to be fetched unauthenticated. No JSON-RPC, no handshake, no `tools/list`,
  no provoked errors, no burst. Verified against a request-logging server: **2 requests instead of
  7**, none of them to the endpoint. Intended for ecosystem surveys where no per-server
  authorisation exists.
- Checks now carry a `passiveSafe` flag; `ScanContext.passive` and `ScanReport.mode` were added.
  Non-passive checks are reported as `SKIPPED` with a reason rather than silently dropped.
- `--passive` is mutually exclusive with `--active` and `--token`; both combinations abort with
  exit code 1 and an explanatory message.
- Terminal and Markdown reports now state the scan mode; the Markdown report carries an explicit
  caveat that a clean passive result says nothing about the server's auth enforcement.

### Fixed
- **Documentation accuracy.** The README described the scan as "nicht invasiv". That was wrong for
  the default run: `unauth-tools` performs a full unauthenticated handshake and enumerates tools,
  and `error-verbosity` deliberately provokes an error response. Both the README and the CLI help
  now describe this and point to `--passive` for the unauthorised case.

## [1.2.0] - 2026-07
### Added
- Check: **protected resource metadata** (`resource-metadata`) — validates RFC 9728 metadata
  (`resource` + `authorization_servers`) and that a 401 advertises `resource_metadata` via
  `WWW-Authenticate`. This is the token-audience / resource-indicator (RFC 8707) control that
  mitigates **token pass-through and confused-deputy** — the central remote-MCP auth gap.
- Check: **session-id entropy** (`session-id-entropy`) — flags weak/guessable `mcp-session-id`
  values (too short, digits-only, dictionary words, low entropy) → session-hijacking risk. The
  emitted id is redacted in the report (never echoed in full).
- 7 new unit tests (14 → 21); both checks exercised by the bundled vulnerable-server self-test.

### Changed
- Check count 10 → 12; version bumped to 1.2.0.
- Version string is now defined once in `src/version.ts` (was duplicated across `scanner.ts` and
  `probe.ts`).

### Fixed
- `--ci` now sets `process.exitCode` instead of calling `process.exit()`. A hard `process.exit()`
  can race with socket/stdout teardown on Windows + Node 24 (a libuv assertion) and corrupt the
  exit code a CI gate relies on; the process now drains cleanly and returns the correct code.

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
- Expand from 10 to 12+ checks. _(Reached 12 in 1.2.0.)_
