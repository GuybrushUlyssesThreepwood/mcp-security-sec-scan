# mcp-sec-scan

**Fokussierter Security-Scanner für Remote-MCP-Server (Auth & Mandantentrennung).**

Zeig ihn auf einen Model-Context-Protocol-Server (Streamable HTTP) und er prüft genau die Dinge, die
darüber entscheiden, ob man KI-Agenten hineinlassen darf: **OAuth 2.1 / PKCE, unauthentifizierter
Zugriff, mandantengefährdendes CORS, Tool-Poisoning, Fehler-Leaks, Rate-Limiting.** Von außen, nicht
invasiv.

> Kein weiterer breiter MCP-Linter. Fokus auf **Auth & Multi-Tenancy** — die Schicht, die No-Code-
> Generatoren und OpenAPI-zu-MCP-Konverter falsch machen. (Anderer Scope als generische Scanner wie
> Invariant `mcp-scan` oder Cisco `mcp-scanner`.)

---

## Warum es das gibt

Remote-MCP-Server entstehen schnell, oft per Generator. Die typischen Fehler sind banal und gefährlich:
Tool-Calls, die ohne Token funktionieren; fehlendes PKCE; Wildcard-CORS mit Credentials; Stacktraces,
die Pfade leaken; Tool-Beschreibungen mit versteckten Anweisungen. `mcp-sec-scan` findet die von außen
sichtbaren davon in Sekunden und erzeugt einen Report, den man einem Kunden geben kann.

## Installation

```bash
npm install -g mcp-sec-scan
# oder ohne Installation ausführen:
npx mcp-sec-scan <url>
```

## Benutzung

```bash
mcp-sec-scan https://example.com/mcp
mcp-sec-scan https://example.com/mcp --active -m report.md
MCP_SEC_SCAN_TOKEN=... mcp-sec-scan https://example.com/mcp   # Tiefen-Checks mit Token
```

| Option | Bedeutung |
|--------|-----------|
| `--token <t>` | Bearer-Token für authentifizierte Tiefen-Checks (oder `MCP_SEC_SCAN_TOKEN`) |
| `-m, --markdown <f>` | Markdown-Report schreiben |
| `--json <f>` | Rohen JSON-Report schreiben |
| `--sarif <f>` | SARIF-2.1.0-Report schreiben (GitHub Code Scanning / Security-Tab) |
| `--active` | Aktive Proben aktivieren (kleiner Rate-Limit-Burst) |
| `--timeout <ms>` | Timeout pro Request (Standard 10000) |
| `--ci` | Exit `2` bei PROBLEM, `1` bei WARN, sonst `0` |

## Beispiel-Ausgabe

```
❌ PROBLEM  Tool listing without authentication
    tools/list without a token succeeded (2 tools visible). The server requires no auth for tool use.
    → Fix: Enforce OAuth 2.1 for all tool operations; reject unauthenticated requests with 401.
❌ PROBLEM  Tool poisoning heuristic
    Suspicious patterns in 1 tool description(s): read_notes: instruction-override, exfiltration hint, secret path
⚠️ WARN     OAuth 2.1 metadata & PKCE (S256)
    No OAuth authorization-server metadata found under standard .well-known paths.
```

Ein vollständiger Beispiel-Report: [`examples/sample-report.md`](examples/sample-report.md).

## Checks (v1.2 — 12 Prüfungen)

1. TLS erzwungen (kein Klartext-HTTP)
2. Authentifizierung erforderlich
3. Security-Header (HSTS, `X-Content-Type-Options: nosniff`)
4. Session-ID-Entropie (schwache/ratbare `mcp-session-id` → Session-Hijacking)
5. Tool-Listing/-Nutzung ohne Authentifizierung
6. OAuth-2.1-Metadaten & PKCE (S256)
7. Protected Resource Metadata (RFC 9728) & Audience-Bindung (RFC 8707 — Token-Passthrough / Confused Deputy)
8. Tool-Poisoning-Heuristik (Beschreibungen)
9. CORS-Konfiguration (Wildcard + Credentials, Origin-Reflection)
10. Origin-Header-Validierung (DNS-Rebinding, Streamable HTTP)
11. Fehler-Ausführlichkeit (Stacktrace-/Secret-Leaks)
12. Rate-Limiting (Burst-Heuristik, `--active`)

## GitHub Action

```yaml
# .github/workflows/mcp-sec-scan.yml
name: MCP Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # nötig zum Hochladen von SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: your-org/mcp-sec-scan/.github/actions/scan@v1
        with:
          url: ${{ vars.MCP_SERVER_URL }}
          token: ${{ secrets.MCP_TOKEN }}
          ci: 'true'
      - name: Upload SARIF to the Security tab
        if: always()   # auch bei fehlgeschlagenem Scan hochladen
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mcp-sec-scan.sarif
```

Findings erscheinen dann unter **Security → Code scanning**, ein Alert pro Check.

## Scope & Grenzen

Dies ist ein **externer, nicht-invasiver** Scan. Er kann das Fehlen interner Probleme nicht beweisen —
z. B. Mandantendaten-Leaks, Vollständigkeit des Audit-Logs oder Injection-Handling in Tool-Parametern.
Dafür braucht es ein vollständiges Audit (mit Zugriff). Berichtet wird, was ein unauthentifizierter —
oder Token-haltender — Client beobachten kann.

## ⚠️ Rechtliches

**Scanne nur Server, die dir gehören oder für die du ausdrücklich autorisiert bist.** Unaufgefordertes
Scannen fremder Systeme kann rechtswidrig sein. Bei einem kostenlosen Scan vorab die dokumentierte
Erlaubnis des Betreibers einholen.

## Tieferes Audit gewünscht?

`mcp-sec-scan` ist der kostenlose Teaser. Ein vollständiges Festpreis-MCP-Security-Audit ergänzt die
internen Checks (Mandantentrennung, Audit-Logging, Injection-Handling) plus Remediation-Schritte —
vollständig asynchron, Report + Loom, keine Meetings. → **[your-domain]**

## Lizenz

Apache-2.0
