# mcp-sec-scan

**Focused security scanner for remote MCP servers (auth & tenant isolation).**

Point it at a Model Context Protocol server (Streamable HTTP) and it checks exactly the things that
decide whether you can let AI agents in: **OAuth 2.1 / PKCE, unauthenticated access, tenant-endangering
CORS, tool poisoning, error leaks, rate limiting.** From the outside and without write access — but
**not purely observational**: the default run performs an unauthenticated MCP handshake, attempts
`tools/list` and deliberately provokes an error response. So: **only with the operator's permission.**
For surveys without a mandate there is
[`--passive`](#--passive--observation-mode-without-a-mandate).

> Not another broad MCP linter. The focus is **auth & multi-tenancy** — the layer no-code generators
> and OpenAPI-to-MCP converters get wrong. (Different scope than generic scanners such as Invariant
> `mcp-scan` or Cisco `mcp-scanner`.)

---

## What is this?

**What it does.** 12 external checks against a remote MCP server (Streamable HTTP) — without write
access, but in the default run not purely observational (see [Legal](#️-legal)): TLS, auth enforcement,
unauthenticated tool access, OAuth 2.1 / PKCE metadata, audience binding, tool poisoning, CORS, origin
validation, error leaks, rate limiting. Output as a terminal report, Markdown, JSON or **SARIF**
(GitHub Code Scanning) — plus a ready-made GitHub Action and CI exit codes.

**Who it is for.** SaaS teams and agencies that build or ship remote MCP servers — especially ones
produced by generators or no-code tooling that touch multi-tenant customer data. Secondary: auditors
who need a fast, presentable first finding.

## Why it exists

Remote MCP servers appear quickly, often generated. The typical mistakes are banal and dangerous:
tool calls that work without a token; missing PKCE; wildcard CORS with credentials; stack traces that
leak paths; tool descriptions carrying hidden instructions. `mcp-sec-scan` finds the externally visible
ones in seconds and produces a report you can hand to a customer.

## Installation

```bash
npm install -g mcp-sec-scan
# or run without installing:
npx mcp-sec-scan <url>
```

The package has **no runtime dependencies** — installing it pulls exactly one set of files, nothing
transitive. For a tool you run inside other people's CI pipelines, that is deliberate.

Building from the repository works too:

```bash
git clone https://github.com/GuybrushUlyssesThreepwood/mcp-security-sec-scan.git
cd mcp-security-sec-scan
npm ci && npm run build && node dist/cli.js <url>
```

## Usage

```bash
mcp-sec-scan https://example.com/mcp
mcp-sec-scan https://example.com/mcp --active -m report.md
MCP_SEC_SCAN_TOKEN=... mcp-sec-scan https://example.com/mcp   # deep checks with a token
```

| Option | Meaning |
|--------|---------|
| `--token <t>` | Bearer token for authenticated deep checks (or `MCP_SEC_SCAN_TOKEN`) |
| `-m, --markdown <f>` | Write a Markdown report |
| `--json <f>` | Write the raw JSON report |
| `--sarif <f>` | Write a SARIF 2.1.0 report (GitHub Code Scanning / Security tab) |
| `--active` | Enable active probes (small rate-limit burst) — **puts load on the target, see Legal** |
| `--passive` | **Observation mode:** no request to the MCP endpoint itself (see below) |
| `--timeout <ms>` | Timeout per request (default 10000) |
| `--ci` | Exit `2` on PROBLEM, `1` on WARN, otherwise `0` |

### `--passive` — observation mode without a mandate

For the case where you have **no** permission from the operator: surveys across many third-party
servers, ecosystem research, preliminary work. In this mode only checks run that **never touch** the
MCP endpoint itself:

- inspection of the URL (TLS)
- `GET /.well-known/oauth-protected-resource` (RFC 9728)
- `GET /.well-known/oauth-authorization-server` (RFC 8414)

Both paths are published by the specification precisely so unauthenticated clients can fetch them —
the same category as a `robots.txt`. **No JSON-RPC, no handshake, no tool listing, no provoked errors,
no burst.**

```bash
mcp-sec-scan https://example.com/mcp --passive --json out.json
```

Measured against a request-logging server that rejects an unauthenticated `initialize`: **2 requests**
(both `.well-known`) instead of **7**, five of which go straight to the endpoint. If a server leaves
`initialize` open — the normal case — the default run continues the handshake and reaches 7 requests
directly at the endpoint. Observation mode stays at 2 in both cases, none of them at the endpoint. The
nine checks that did not run appear in the report as `SKIPPED` with a reason — visible on purpose
rather than silently dropped.

⚠️ **A clean result in observation mode says nothing about the server's auth enforcement.** Whether
`tools/list` works without a token is exactly the question this mode does not ask. Anyone who needs a
defensible answer needs the full scan — and therefore the permission.

`--passive` is mutually exclusive with `--active` and `--token`; both combinations abort with exit
code 1.

## Example output

```
❌ PROBLEM  Tool listing without authentication
    tools/list without a token succeeded (2 tools visible). The server requires no auth for tool use.
    → Fix: Enforce OAuth 2.1 for all tool operations; reject unauthenticated requests with 401.
❌ PROBLEM  Tool poisoning heuristic
    Suspicious patterns in 1 tool description(s): read_notes: instruction-override, exfiltration hint, secret path
⚠️ WARN     OAuth 2.1 metadata & PKCE (S256)
    No OAuth authorization-server metadata found under standard .well-known paths.
```

A full example report: [`examples/sample-report.md`](examples/sample-report.md).

## Checks (12)

1. TLS enforced (no cleartext HTTP)
2. Authentication required
3. Security headers (HSTS, `X-Content-Type-Options: nosniff`)
4. Session-id entropy (weak/guessable `mcp-session-id` -> session hijacking)
5. Tool listing/use without authentication
6. OAuth 2.1 metadata & PKCE (S256)
7. Protected resource metadata (RFC 9728) & audience binding (RFC 8707 — token pass-through / confused deputy)
8. Tool-poisoning heuristic (descriptions)
9. CORS configuration (wildcard + credentials, origin reflection)
10. Origin header validation (DNS rebinding, Streamable HTTP)
11. Error verbosity (stack trace / secret leaks)
12. Rate limiting (burst heuristic, `--active`)

## GitHub Action

```yaml
# .github/workflows/mcp-sec-scan.yml
name: MCP Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # needed to upload SARIF
    steps:
      - uses: actions/checkout@v4
      # Pin to a commit SHA once a release tag exists — a moving ref runs
      # third-party code in your CI as soon as it changes.
      - uses: GuybrushUlyssesThreepwood/mcp-security-sec-scan/.github/actions/scan@main
        with:
          url: ${{ vars.MCP_SERVER_URL }}
          token: ${{ secrets.MCP_TOKEN }}
          ci: 'true'
      - name: Upload SARIF to the Security tab
        if: always()   # upload even when the scan failed
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mcp-sec-scan.sarif
```

Findings then show up under **Security -> Code scanning**, one alert per check.

## Scope & limits

This is an **external** scan without write access — but the default run is not purely observational
(handshake, `tools/list`, provoked error response; with `--active` an additional burst). Only
`--passive` is observation-only. It cannot prove the absence of internal problems — tenant data leaks,
audit-log completeness or injection handling in tool parameters, for example. That needs a full audit
(with access). What is reported is what an unauthenticated — or token-carrying — client can observe.

## ⚠️ Legal

**Only scan servers you own or are explicitly authorised to test.** Unsolicited scanning of
third-party systems may be unlawful (in Germany, among others, §§ 202a et seq. and § 303b of the
Criminal Code). For a free scan, obtain the operator's documented permission first.

**The default run already requires that permission, not just `--active`.** It addresses the MCP
endpoint itself: unauthenticated handshake, `tools/list`, a deliberately provoked error response and a
request carrying a foreign `Origin` header. Only `--passive` is purely observational.

**`--active` needs a further, explicit permission on top.** It additionally sends a short request burst
to detect rate limiting — the only check that puts measurable load on the target and that may, in the
worst case, trigger alerts or degrade a tightly sized server. That is why it is off by default. Enable
it only when the permission explicitly covers active probing, and preferably outside peak hours.

**Document the permission before you scan** — who granted it, for which target system, for which
period, with or without active probes. Without that record there is no basis in a dispute, and
professional indemnity insurers regularly cover testing work only where the system operator has
mandated and authorised it.

## Want a deeper audit?

`mcp-sec-scan` is the free teaser. A full fixed-price MCP security audit adds the internal checks
(tenant isolation, audit logging, injection handling) plus remediation steps — fully asynchronous,
report plus a recorded walkthrough, no meetings. -> **https://www.honrodt.de** (dedicated product
domain to follow)

## Provider

Yimmie Honrodt, sole proprietorship, Cologne, Germany — **provider identification under § 5 DDG:**
https://honrodt.de/impressum · Contact: kontakt@honrodt.de

## License

Apache-2.0

---

## Liability and warranty

This project is licensed under the **Apache License 2.0** and is provided as is ("AS IS", without
warranties or conditions of any kind). Liability for damages arising from its use is excluded to the
extent permitted by law — see `LICENSE`, sections 7 and 8, for details.

**A scan does not replace a full security assessment.** It covers the checks it implements, no more.
A run without findings does not mean a server is secure. Responsibility for operating and securing
the scanned systems remains with the operator.

**Only test third-party systems with the operator's documented permission.** Without authorisation
even a scan can be unlawful.
