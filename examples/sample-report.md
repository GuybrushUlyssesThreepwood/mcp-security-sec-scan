# MCP Security Scan Report

**Target:** `http://127.0.0.1:8971/`  
**Scanned:** 2026-08-30T09:29:16.009Z  
**Scanner:** mcp-sec-scan v1.3.1  
**Mode:** standard (external scan)

## Summary

| Severity | Count |
|----------|------:|
| ❌ Problem | 5 |
| ⚠️ Warn | 5 |
| ✅ Pass | 0 |
| ℹ️ Info | 2 |
| ⏭️ Skipped | 0 |

## Findings

### ❌ PROBLEM — TLS enforced (no cleartext HTTP)

The endpoint uses 'http:' instead of HTTPS. Tokens and data would travel in cleartext.

**Remediation:** Serve remote MCP over HTTPS only; redirect HTTP to HTTPS or refuse it.

_Reference: MCP Security Checklist #15_

### ❌ PROBLEM — Tool listing without authentication

tools/list without a token succeeded (2 tools visible). The server requires no auth for tool use.

**Remediation:** Enforce OAuth 2.1 for all tool operations; reject unauthenticated requests with 401.

_Reference: MCP Security Checklist #1_

### ❌ PROBLEM — Tool poisoning heuristic

Suspicious patterns in 1 tool description(s):  
- read_notes: instruction-override, concealment instruction, exfiltration hint, secret path

**Remediation:** Curate and sanitise tool metadata; version descriptions (rug-pull protection); mark untrusted content.

_Reference: MCP Security Checklist #9 Tool Poisoning_

### ❌ PROBLEM — CORS configuration

ACAO '*' together with Allow-Credentials 'true' — an unsafe combination (credentials for every origin).

**Remediation:** No wildcard with credentials. Use an origin allow-list.

_Reference: MCP Security Checklist #15_

### ❌ PROBLEM — Error verbosity (stack traces/secrets)

The error response contains revealing details (pattern: /traceback \(most recent call last\)/). It can expose paths, internals or secrets.

**Remediation:** Return generic errors outward; log details internally only. Redact secrets.

_Reference: MCP Security Checklist A1/A2/A6, B_

### ⚠️  WARN — Security headers (HSTS, nosniff)

Missing security headers: X-Content-Type-Options: nosniff.

**Remediation:** Over HTTPS, set 'Strict-Transport-Security: max-age=15552000; includeSubDomains' and send 'X-Content-Type-Options: nosniff'.

_Reference: MCP Security Checklist #15_

### ⚠️  WARN — Session-id unpredictability (mcp-session-id)

The issued 'mcp-session-id' (test…, 12 characters) looks weak: too short (12 characters, < 16). Guessable or brute-forceable -> risk of session hijacking.

**Remediation:** Use cryptographically secure session ids (CSPRNG, >=128 bits of entropy, e.g. crypto.randomUUID); do not derive them sequentially or from plaintext.

_Reference: MCP Security Checklist Session-Hijacking_

### ⚠️  WARN — OAuth 2.1 metadata & PKCE (S256)

No OAuth authorization-server metadata found under standard .well-known paths. Either no OAuth (problematic for remote servers) or a non-standard discovery path.

**Remediation:** Provide OAuth 2.1 with published metadata (RFC 8414/9728) for remote MCP.

_Reference: MCP Security Checklist A1/A2/A6, B_

### ⚠️  WARN — Origin header validation (DNS rebinding)

The server accepts 'initialize' with a foreign origin (https://dns-rebind.attacker.example, HTTP 200) without refusing it. The MCP Streamable HTTP specification requires origin validation against DNS rebinding — especially critical for servers reachable locally or on an internal network.

**Remediation:** Check the Origin header against a fixed allow-list and refuse foreign origins with 403; bind the server only to the interfaces it needs.

_Reference: MCP Security Checklist #15_

### ⚠️  WARN — Rate limiting (burst heuristic)

Burst of 12 requests without a single 429 response. No externally detectable rate limiting (heuristic — the threshold may simply be higher).

**Remediation:** Introduce rate limits per tenant/client/tool and budget caps for expensive operations.

_Reference: MCP Security Checklist #12 Rate-Limiting_

### ℹ️  INFO — Authentication enforced

Server answers 'initialize' without a token (HTTP 200). Harmless in itself — what matters is whether tool calls are possible without a token (see the 'unauth-tools' check).

_Reference: MCP Security Checklist A1/A2/A6, B_

### ℹ️  INFO — Protected resource metadata (RFC 9728) & audience binding

No RFC 9728 protected resource metadata found. The spec expects it for a token-protected remote MCP server — but no auth is enforced here, so this is informational only.

**Remediation:** If OAuth-protected: publish RFC 9728 metadata (resource + authorization_servers).

_Reference: MCP Security Checklist A2/A6 (Token-Audience, RFC 8707/9728)_

---

> This is an **external** scan without write access — but **not purely observational**: it performs an unauthenticated MCP handshake, attempts `tools/list`, deliberately provokes an error response and sends a request with a foreign `Origin` header. It does not prove the absence of internal issues (tenant isolation, audit logging, injection handling in tool parameters). A full audit adds those. Scan only servers you own or are explicitly authorised to test.
