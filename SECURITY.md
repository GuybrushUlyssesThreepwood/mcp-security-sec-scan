# Security Policy

## Reporting a vulnerability
If you find a security issue in `mcp-sec-scan` itself, please report it **privately**:

- Email: **kontakt@honrodt.de** (Geschäftsadresse; eine eigene Produkt-Domain folgt)
- Or use GitHub's **private vulnerability reporting** (Security tab → "Report a vulnerability").

Please do **not** open a public issue for security reports. We aim to acknowledge within **3 business days**
and to agree a coordinated disclosure timeline.

## Scope
`mcp-sec-scan` is a scanner. It performs **external** checks against MCP servers, without write
access — but the default run is **not purely observational**: it opens an unauthenticated MCP
handshake, attempts `tools/list`, deliberately provokes an error response and sends a request
carrying a foreign `Origin` header. Only `--passive` is observation-only; it touches nothing but the
standardised `.well-known` discovery paths.

## Responsible use
This tool must only be run against servers you **own** or are **explicitly authorised** to test.
Unsolicited scanning of third-party systems may be unlawful. The maintainers accept no liability for misuse.

Document the authorisation **before** you scan: who granted it, for which target, for which period,
and whether it covers active probing.

**The default run already requires that authorisation** — it is not a passive observation. Use
`--passive` when you have no mandate (ecosystem surveys, pre-research); it sends no request to the
MCP endpoint itself, and a clean result there says nothing about the server's auth enforcement.

`--active` needs a further, separate permission on top: it sends a short request burst to detect
rate limiting. It is the only check that puts measurable load on the target, so it is off by default.
Enable it only when the authorisation covers active probing, and preferably outside peak hours.

## Supported versions
The latest `1.x` release receives security fixes.
