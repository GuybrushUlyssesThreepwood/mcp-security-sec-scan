# Changelog

All notable changes to `mcp-sec-scan` are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/); this project uses semantic versioning.

> **Note on earlier entries.** Up to 1.2.0 this file listed release dates that did not match the
> repository: `1.2.0` was dated to July although its checks were first committed on 2026-08-29, and
> `1.0.0` was dated *after* `1.1.0`. The entries below were corrected against `git log`. Nothing was
> ever published to a package registry, so no released artifact is affected.

## [1.3.0] - 2026-08-29
### Fixed
- **False positive in `unauth-tools`, the tool's central check.** A `tools/list` answered with a
  JSON-RPC `error` object over HTTP 200 — the encoding JSON-RPC 2.0 §5.1 prescribes — was read as a
  successful listing, because the code fell back to an empty tool array and tested it for
  truthiness. A server that correctly refuses unauthenticated tool use was reported as
  `PROBLEM: tools/list without a token succeeded (0 tools visible)`, which also drove CI exit code 2
  and a SARIF `error` alert. JSON-RPC errors now count as a refusal (`PASS`), and a genuinely empty
  list is `INFO`, not `PROBLEM`.
- **False positives in `oauth-metadata-pkce` and `resource-metadata`.** Neither verified that the
  fetched document actually was the metadata document. Servers with a catch-all that answers every
  path with HTTP 200 and some JSON were reported as "PKCE/S256 missing" (`PROBLEM`) or "metadata
  without `resource`" (`WARN`). Both now require the mandatory field of the respective RFC
  (`issuer` for RFC 8414, `resource`/`authorization_servers` for RFC 9728).
- **Command injection in the bundled GitHub Action.** Inputs were interpolated into the `run:`
  script via `${{ }}`, i.e. spliced into the command line before the shell parsed it — a crafted
  `url` input could execute arbitrary code on the runner, with the bearer token in the same
  environment. All inputs now travel through `env:` and are dereferenced as quoted shell variables.
- **The Action no longer installs the scanner from a package registry.** It ran
  `npx --yes mcp-sec-scan@^1`, and that npm name is unregistered — whoever claimed it would have
  gained code execution in every consumer's CI, plus their MCP token. The Action now builds from
  its own repository checkout.
- **Documentation accuracy, completed.** The scan was described as "nicht invasiv" / "non-invasive"
  in six places. That is wrong for the default run: `unauth-tools` performs a full unauthenticated
  handshake and enumerates tools, `error-verbosity` deliberately provokes an error response and
  `origin-validation` sends a foreign `Origin` header. README, CLI help, `SECURITY.md`,
  `CONTRIBUTING.md`, the templates and the Markdown report footer now say so and point to
  `--passive` for the unauthorised case. 1.2.0 corrected only part of this.
- `tool-poisoning` no longer flags the bare word `password`; a tool that legitimately takes a
  password parameter is not a poisoning finding.
- `security-headers` and `session-id-entropy` no longer send the bearer token in their fallback
  probe, whose result is stored as `shared.unauthInitialize` and drives the auth inference in
  `resource-metadata`.
- Report references no longer carry the internal ticket id `T-003`.
- SARIF `helpUri` / `informationUri` pointed at the repository's former name.
- The README documented `npm install -g mcp-sec-scan`, which does not work — the package is not
  published. It now documents the build-from-source path.

### Added
- The CLI rejects any target that is not an `http(s)` URL instead of letting it fail later as a
  network error.

### Removed
- Unused dependency `@modelcontextprotocol/sdk`. The prober is deliberately SDK-free; the package
  was never imported and only widened the supply-chain surface.

## [1.2.0] - 2026-08-29
### Added
- **`--passive` observation mode.** Runs only checks that never touch the MCP endpoint itself:
  URL/TLS inspection plus `GET` on the standardised `.well-known` discovery paths (RFC 8414 /
  RFC 9728), which exist to be fetched unauthenticated. No JSON-RPC, no handshake, no `tools/list`,
  no provoked errors, no burst. Against a request-logging server that rejects unauthenticated
  `initialize`: **2 requests instead of 7**, none of them to the endpoint. Intended for ecosystem
  surveys where no per-server authorisation exists.
- Checks now carry a `passiveSafe` flag; `ScanContext.passive` and `ScanReport.mode` were added.
  Non-passive checks are reported as `SKIPPED` with a reason rather than silently dropped.
- `--passive` is mutually exclusive with `--active` and `--token`; both combinations abort with
  exit code 1 and an explanatory message.
- Terminal and Markdown reports state the scan mode; the Markdown report carries an explicit caveat
  that a clean passive result says nothing about the server's auth enforcement.
- Check: **protected resource metadata** (`resource-metadata`) — validates RFC 9728 metadata
  (`resource` + `authorization_servers`) and that a 401 advertises `resource_metadata` via
  `WWW-Authenticate`. This is the token-audience / resource-indicator (RFC 8707) control that
  mitigates **token pass-through and confused-deputy** — the central remote-MCP auth gap.
- Check: **session-id entropy** (`session-id-entropy`) — flags weak/guessable `mcp-session-id`
  values (too short, digits-only, dictionary words, low entropy) → session-hijacking risk. The
  emitted id is redacted in the report (never echoed in full).
- 7 new unit tests (14 → 21).

### Changed
- Check count 10 → 12.
- Version string is now defined once in `src/version.ts` (was duplicated across `scanner.ts` and
  `probe.ts`).

### Fixed
- **Documentation accuracy (partial).** The README described the scan as "nicht invasiv". That is
  wrong for the default run. README intro, scope section and CLI help were corrected here; the
  remaining places followed in 1.3.0.
- `--ci` now sets `process.exitCode` instead of calling `process.exit()`. A hard `process.exit()`
  can race with socket/stdout teardown on Windows + Node 24 (a libuv assertion) and corrupt the
  exit code a CI gate relies on; the process now drains cleanly and returns the correct code.

## [1.1.0] - 2026-07-07
### Added
- Check: **security headers** — flags missing HSTS (over HTTPS) and `X-Content-Type-Options: nosniff`.
- Check: **origin-header validation** — sends `initialize` with a foreign `Origin` and flags servers that
  accept it, per the MCP Streamable HTTP requirement to validate Origin against DNS-rebinding attacks.
- **SARIF 2.1.0 output** (`--sarif <file>`) for GitHub Code Scanning; the reusable Action emits it by
  default and the README shows the `upload-sarif` step (results land in the Security tab).
- 5 new unit tests; new checks exercised by the bundled vulnerable-server self-test.

### Changed
- Check count 8 → 10.

## [1.0.0] - 2026-07-07
### Added
- CLI `mcp-sec-scan <url>` for remote MCP servers (Streamable HTTP).
- 8 checks: TLS enforced, authentication required, unauthenticated tool listing, OAuth 2.1 metadata & PKCE
  (S256), tool-poisoning heuristic, CORS configuration, error verbosity, rate limiting (`--active`).
- Markdown and JSON report export; colored terminal output.
- `--ci` mode with meaningful exit codes (2 = problem, 1 = warn, 0 = clean).
- Reusable GitHub Action (`.github/actions/scan`).
- `--token` / `MCP_SEC_SCAN_TOKEN` for authenticated deep checks.
- Bundled intentionally-vulnerable test server + CI self-test; unit tests.
