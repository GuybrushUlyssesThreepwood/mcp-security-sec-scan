# Security Policy

## Reporting a vulnerability
If you find a security issue in `mcp-sec-scan` itself, please report it **privately**:

- Email: **kontakt@honrodt.de** (Geschäftsadresse; eine eigene Produkt-Domain folgt)
- Or use GitHub's **private vulnerability reporting** (Security tab → "Report a vulnerability").

Please do **not** open a public issue for security reports. We aim to acknowledge within **3 business days**
and to agree a coordinated disclosure timeline.

## Scope
`mcp-sec-scan` is a scanner. It performs **external, non-invasive** checks against MCP servers.

## Responsible use
This tool must only be run against servers you **own** or are **explicitly authorised** to test.
Unsolicited scanning of third-party systems may be unlawful. The maintainers accept no liability for misuse.

Document the authorisation **before** you scan: who granted it, for which target, for which period,
and whether it covers active probing.

`--active` needs its own, explicit permission. The default checks are purely observational; `--active`
additionally sends a short request burst to detect rate limiting. It is the only check that puts
measurable load on the target, so it is off by default. Enable it only when the authorisation covers
active probing, and preferably outside peak hours.

## Supported versions
The latest `1.x` release receives security fixes.
