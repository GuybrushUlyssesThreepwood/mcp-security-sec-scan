# mcp-sec-scan

**Fokussierter Security-Scanner für Remote-MCP-Server (Auth & Mandantentrennung).**

Zeig ihn auf einen Model-Context-Protocol-Server (Streamable HTTP) und er prüft genau die Dinge, die
darüber entscheiden, ob man KI-Agenten hineinlassen darf: **OAuth 2.1 / PKCE, unauthentifizierter
Zugriff, mandantengefährdendes CORS, Tool-Poisoning, Fehler-Leaks, Rate-Limiting.** Von außen und
ohne Schreibzugriff — aber **nicht rein beobachtend**: der Standardlauf führt einen
unauthentifizierten MCP-Handshake durch, versucht `tools/list` und provoziert bewusst eine
Fehlerantwort. Deshalb gilt: **nur mit Erlaubnis des Betreibers.** Für Erhebungen ohne Auftrag gibt es
[`--passive`](#--passive--beobachtungsmodus-ohne-auftrag).

> Kein weiterer breiter MCP-Linter. Fokus auf **Auth & Multi-Tenancy** — die Schicht, die No-Code-
> Generatoren und OpenAPI-zu-MCP-Konverter falsch machen. (Anderer Scope als generische Scanner wie
> Invariant `mcp-scan` oder Cisco `mcp-scanner`.)

---

## Was ist das?

**Was es kann.** 12 externe, nicht-invasive Prüfungen gegen einen Remote-MCP-Server (Streamable HTTP):
TLS, Auth-Pflicht, unauth. Tool-Zugriff, OAuth-2.1/PKCE-Metadaten, Audience-Bindung, Tool-Poisoning,
CORS, Origin-Validierung, Fehler-Leaks, Rate-Limiting. Ausgabe als Terminal-Report, Markdown, JSON oder
**SARIF** (GitHub Code Scanning) — plus fertige GitHub Action und CI-Exit-Codes.

**Für wen.** SaaS-Teams und Agenturen, die Remote-MCP-Server bauen oder ausliefern — besonders solche,
die per Generator/No-Code entstehen und Multi-Tenant-Kundendaten berühren. Sekundär: Auditoren, die
einen schnellen, vorzeigbaren Erst-Befund brauchen.

**Rolle im Geschäft / Erwartung.** Das kostenlose Tür-Produkt (Tickets T-101/102). Der Scan ist der
Teaser; jeder Report endet mit dem Weg zum bezahlten Festpreis-Audit (async, Report + Loom, keine
Meetings) und, laufend, zum Retainer. Zweck: Reputation über OSS, Vertrauen ohne Call, Einstieg in den
Funnel.

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
| `--active` | Aktive Proben aktivieren (kleiner Rate-Limit-Burst) — **erzeugt Last auf dem Ziel, siehe Rechtliches** |
| `--passive` | **Beobachtungsmodus:** keine Anfrage an den MCP-Endpunkt selbst (siehe unten) |
| `--timeout <ms>` | Timeout pro Request (Standard 10000) |
| `--ci` | Exit `2` bei PROBLEM, `1` bei WARN, sonst `0` |

### `--passive` — Beobachtungsmodus ohne Auftrag

Für den Fall, dass du **keine** Erlaubnis des Betreibers hast: Erhebungen über viele fremde Server,
Ökosystem-Auswertungen, Vorab-Recherche. In diesem Modus laufen ausschließlich Prüfungen, die den
MCP-Endpunkt selbst **nicht ansprechen**:

- Auswertung der URL (TLS)
- `GET /.well-known/oauth-protected-resource` (RFC 9728)
- `GET /.well-known/oauth-authorization-server` (RFC 8414)

Diese beiden Pfade werden von der Spezifikation genau dafür veröffentlicht, von unauthentifizierten
Clients abgerufen zu werden — dieselbe Kategorie wie eine `robots.txt`. **Kein JSON-RPC, kein
Handshake, keine Tool-Auflistung, keine provozierten Fehler, kein Burst.**

```bash
mcp-sec-scan https://example.com/mcp --passive --json out.json
```

Gemessen gegen einen protokollierenden Server: **2 Requests** (beide `.well-known`) statt **7** im
Standardlauf, davon 5 direkt auf den Endpunkt. Die neun nicht ausgeführten Checks erscheinen im
Report als `SKIPPED` mit Begründung — bewusst sichtbar statt still weggelassen.

⚠️ **Ein sauberes Ergebnis im Beobachtungsmodus sagt nichts über die Auth-Durchsetzung des Servers
aus.** Ob `tools/list` ohne Token funktioniert, ist genau die Frage, die dieser Modus nicht stellt.
Wer eine belastbare Aussage braucht, braucht den vollen Scan — und damit die Erlaubnis.

`--passive` schließt `--active` und `--token` aus; beides bricht mit Exit-Code 1 ab.

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
      - uses: GuybrushUlyssesThreepwood/mcp-security-sec-scan/.github/actions/scan@v1
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

Dies ist ein **externer** Scan ohne Schreibzugriff — im Standardlauf aber nicht rein beobachtend
(Handshake, `tools/list`, provozierte Fehlerantwort; mit `--active` zusätzlich ein Burst).
Rein beobachtend ist nur `--passive`. Er kann das Fehlen interner Probleme nicht beweisen —
z. B. Mandantendaten-Leaks, Vollständigkeit des Audit-Logs oder Injection-Handling in Tool-Parametern.
Dafür braucht es ein vollständiges Audit (mit Zugriff). Berichtet wird, was ein unauthentifizierter —
oder Token-haltender — Client beobachten kann.

## ⚠️ Rechtliches

**Scanne nur Server, die dir gehören oder für die du ausdrücklich autorisiert bist.** Unaufgefordertes
Scannen fremder Systeme kann rechtswidrig sein (in Deutschland u. a. §§ 202a ff., 303b StGB). Bei einem
kostenlosen Scan vorab die dokumentierte Erlaubnis des Betreibers einholen.

**`--active` braucht eine ausdrückliche Erlaubnis.** Die Standardprüfungen sind rein beobachtend.
`--active` sendet zusätzlich einen kurzen Anfragen-Burst, um Rate-Limiting zu erkennen — das ist die
einzige Prüfung, die messbare Last auf dem Ziel erzeugt und im ungünstigen Fall Alarme auslöst oder
einen knapp dimensionierten Server beeinträchtigt. Deshalb ist sie standardmäßig aus. Nur einschalten,
wenn die Erlaubnis das aktive Prüfen ausdrücklich abdeckt, und möglichst außerhalb von Lastspitzen.

**Dokumentiere die Erlaubnis, bevor du scannst** — wer, für welches Zielsystem, in welchem Zeitraum,
mit oder ohne aktive Proben. Ohne diesen Nachweis fehlt im Streitfall die Grundlage, und
Berufshaftpflichtversicherer decken Prüftätigkeiten regelmäßig nur mit Beauftragung und Berechtigung
durch den Systembetreiber.

## Tieferes Audit gewünscht?

`mcp-sec-scan` ist der kostenlose Teaser. Ein vollständiges Festpreis-MCP-Security-Audit ergänzt die
internen Checks (Mandantentrennung, Audit-Logging, Injection-Handling) plus Remediation-Schritte —
vollständig asynchron, Report + Loom, keine Meetings. → **https://www.honrodt.de** (eigene Produkt-Domain folgt)

## Lizenz

Apache-2.0

---

## Haftung und Gewährleistung

Dieses Projekt steht unter der **Apache-Lizenz 2.0** und wird ohne Mängelgewähr bereitgestellt
(„AS IS", ohne Gewährleistungen oder Bedingungen gleich welcher Art). Eine Haftung für Schäden aus
der Nutzung ist im gesetzlich zulässigen Rahmen ausgeschlossen — Einzelheiten in `LICENSE`,
Abschnitte 7 und 8.

**Ein Scan ersetzt keine vollständige Sicherheitsprüfung.** Er deckt die implementierten Prüfungen
ab, nicht mehr. Ein Lauf ohne Befund bedeutet nicht, dass ein Server sicher ist. Die Verantwortung
für Betrieb und Absicherung der geprüften Systeme bleibt beim Betreiber.

**Fremde Systeme nur mit dokumentierter Erlaubnis des Betreibers prüfen.** Ohne Berechtigung kann
schon ein Scan rechtswidrig sein.
