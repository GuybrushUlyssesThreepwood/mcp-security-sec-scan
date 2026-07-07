# mcp-sec-scan

**Opinionated remote-MCP auth & tenancy security scanner.**

Point it at a Model Context Protocol server (Streamable HTTP) and it checks the things that actually
decide whether it's safe to let AI agents in: **OAuth 2.1 / PKCE, unauthenticated access, tenant-facing
CORS, tool poisoning, error leakage, rate limiting.** From the outside, non-invasively.

> Not another broad MCP linter. Focused on **auth & multi-tenancy** — the layer that no-code generators
> and OpenAPI-to-MCP converters get wrong. (Different scope than the broad, generic scanners such as
> Invariant `mcp-scan` or Cisco `mcp-scanner`.)

---

## Why this exists

Remote MCP servers are shipping fast, often via generators. The common failures are boring and dangerous:
tool calls that work without a token, missing PKCE, wildcard CORS with credentials, stack traces leaking
paths, tool descriptions carrying hidden instructions. `mcp-sec-scan` finds the externally visible ones in
seconds and produces a report you can hand to a client.

## Install

```bash
npm install -g mcp-sec-scan
# or run without installing:
npx mcp-sec-scan <url>
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
| `--active` | Enable active probes (small rate-limit burst) |
| `--timeout <ms>` | Per-request timeout (default 10000) |
| `--ci` | Exit `2` on any PROBLEM, `1` on any WARN, else `0` |

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

A full sample report: [`examples/sample-report.md`](examples/sample-report.md).

## Checks (v1.1)

1. TLS enforced (no cleartext HTTP)
2. Authentication required
3. Security headers (HSTS, `X-Content-Type-Options: nosniff`)
4. Tool listing/use without authentication
5. OAuth 2.1 metadata & PKCE (S256)
6. Tool-poisoning heuristic (descriptions)
7. CORS configuration (wildcard + credentials, origin reflection)
8. Origin-header validation (DNS-rebinding, Streamable HTTP)
9. Error verbosity (stack traces / secret leakage)
10. Rate limiting (burst heuristic, `--active`)

_Backlog: SARIF output, 12+ checks. See issues._

## GitHub Action

```yaml
# .github/workflows/mcp-sec-scan.yml
name: MCP Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: your-org/mcp-sec-scan/.github/actions/scan@v1
        with:
          url: ${{ vars.MCP_SERVER_URL }}
          token: ${{ secrets.MCP_TOKEN }}
          ci: 'true'
```

## Scope & limits

This is an **external, non-invasive** scan. It cannot prove the absence of internal issues such as
tenant-data leakage, audit-log completeness, or injection handling inside tool parameters. Those need a
full audit (with access). It reports what an unauthenticated — or token-holding — client can observe.

## ⚠️ Legal

**Scan only servers you own or are explicitly authorized to test.** Unsolicited scanning of third-party
systems may be unlawful. When offering a free scan, obtain the operator's documented permission first.

## Want a deeper audit?

`mcp-sec-scan` is the free teaser. A full fixed-price MCP security audit adds the internal checks
(tenant isolation, audit logging, injection handling) plus remediation steps — fully async, report + Loom,
no meetings. → **[your-domain]**

## License

Apache-2.0
