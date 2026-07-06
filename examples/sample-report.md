# MCP Security Scan Report

**Target:** `http://127.0.0.1:8971/`  
**Scanned:** 2026-07-06T22:10:59.075Z  
**Scanner:** mcp-sec-scan v1.0.0

## Summary

| Severity | Count |
|----------|------:|
| ❌ Problem | 5 |
| ⚠️ Warn | 2 |
| ✅ Pass | 0 |
| ℹ️ Info | 1 |
| ⏭️ Skipped | 0 |

## Findings

### ❌ PROBLEM — TLS erzwungen (kein Klartext-HTTP)

Endpoint nutzt 'http:' statt HTTPS. Tokens/Daten wären im Klartext übertragbar.

**Remediation:** Remote-MCP ausschließlich über HTTPS; HTTP auf HTTPS umleiten oder ablehnen.

_Reference: MCP Security Checklist #15 (T-003)_

### ❌ PROBLEM — Tool-Auflistung ohne Authentifizierung

tools/list ohne Token erfolgreich (2 Tools sichtbar). Der Server verlangt keine Authentifizierung für die Tool-Nutzung.

**Remediation:** OAuth 2.1 für alle Tool-Operationen erzwingen; unauthentifizierte Requests mit 401 abweisen.

_Reference: MCP Security Checklist #1 (T-003)_

### ❌ PROBLEM — Tool-Poisoning-Heuristik (Beschreibungen)

Verdächtige Muster in 1 Tool-Beschreibung(en):  
- read_notes: Instruktions-Override, Verschleierungs-Anweisung, Exfiltrations-Hinweis, Secret-/Dateipfad-Referenz

**Remediation:** Tool-Metadaten kuratieren/sanitizen; Beschreibungen versionieren (Rug-Pull-Schutz); untrusted content markieren.

_Reference: MCP Security Checklist #9 Tool Poisoning (T-003)_

### ❌ PROBLEM — CORS-Konfiguration

ACAO '*' zusammen mit Allow-Credentials 'true' — unsichere Kombination (Credentials für jeden Origin).

**Remediation:** Keine Wildcard mit Credentials. Origin-Allowlist verwenden.

_Reference: MCP Security Checklist #15 (T-003)_

### ❌ PROBLEM — Fehler-Verbosity (Stacktraces/Secrets)

Fehlerantwort enthält verräterische Details (Muster: /traceback \(most recent call last\)/). Kann Pfade/Interna/Secrets preisgeben.

**Remediation:** Nach außen generische Fehler; Details nur intern loggen. Secrets redigieren.

_Reference: MCP Security Checklist A1/A2/A6, B (T-003)_

### ⚠️  WARN — OAuth 2.1 Metadaten & PKCE (S256)

Keine OAuth-Authorization-Server-Metadaten unter den Standard-.well-known-Pfaden gefunden. Entweder kein OAuth (bei Remote-Servern problematisch) oder abweichender Discovery-Pfad.

**Remediation:** Für Remote-MCP OAuth 2.1 mit veröffentlichten Metadaten (RFC 8414/9728) bereitstellen.

_Reference: MCP Security Checklist A1/A2/A6, B (T-003)_

### ⚠️  WARN — Rate-Limiting (Burst-Heuristik)

Burst von 12 Requests ohne einzige 429-Antwort. Kein von außen erkennbares Rate-Limiting (Heuristik — evtl. höhere Schwelle).

**Remediation:** Rate-Limits pro Tenant/Client/Tool und Budget-Caps für teure Operationen einführen.

_Reference: MCP Security Checklist #12 Rate-Limiting (T-003)_

### ℹ️  INFO — Authentifizierung erzwungen

Server antwortet auf 'initialize' ohne Token (HTTP 200). Für sich genommen unkritisch — entscheidend ist, ob Tool-Aufrufe ohne Token möglich sind (siehe Check 'unauth-tools').

_Reference: MCP Security Checklist A1/A2/A6, B (T-003)_

---

> This is an **external, non-invasive** scan: it only observes what the server exposes without a valid token or with a token you provided. It does not prove the absence of internal issues (tenant isolation, audit logging, injection handling in tool parameters). A full audit adds those. Scan only servers you own or are explicitly authorized to test.
