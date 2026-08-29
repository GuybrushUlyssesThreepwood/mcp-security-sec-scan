# MCP Security Scan Report

**Target:** `http://127.0.0.1:8971/`  
**Scanned:** 2026-08-29T20:54:25.582Z  
**Scanner:** mcp-sec-scan v1.3.0  
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

### ❌ PROBLEM — TLS erzwungen (kein Klartext-HTTP)

Endpoint nutzt 'http:' statt HTTPS. Tokens/Daten wären im Klartext übertragbar.

**Remediation:** Remote-MCP ausschließlich über HTTPS; HTTP auf HTTPS umleiten oder ablehnen.

_Reference: MCP Security Checklist #15_

### ❌ PROBLEM — Tool-Auflistung ohne Authentifizierung

tools/list ohne Token erfolgreich (2 Tools sichtbar). Der Server verlangt keine Authentifizierung für die Tool-Nutzung.

**Remediation:** OAuth 2.1 für alle Tool-Operationen erzwingen; unauthentifizierte Requests mit 401 abweisen.

_Reference: MCP Security Checklist #1_

### ❌ PROBLEM — Tool-Poisoning-Heuristik (Beschreibungen)

Verdächtige Muster in 1 Tool-Beschreibung(en):  
- read_notes: Instruktions-Override, Verschleierungs-Anweisung, Exfiltrations-Hinweis, Secret-/Dateipfad-Referenz

**Remediation:** Tool-Metadaten kuratieren/sanitizen; Beschreibungen versionieren (Rug-Pull-Schutz); untrusted content markieren.

_Reference: MCP Security Checklist #9 Tool Poisoning_

### ❌ PROBLEM — CORS-Konfiguration

ACAO '*' zusammen mit Allow-Credentials 'true' — unsichere Kombination (Credentials für jeden Origin).

**Remediation:** Keine Wildcard mit Credentials. Origin-Allowlist verwenden.

_Reference: MCP Security Checklist #15_

### ❌ PROBLEM — Fehler-Verbosity (Stacktraces/Secrets)

Fehlerantwort enthält verräterische Details (Muster: /traceback \(most recent call last\)/). Kann Pfade/Interna/Secrets preisgeben.

**Remediation:** Nach außen generische Fehler; Details nur intern loggen. Secrets redigieren.

_Reference: MCP Security Checklist A1/A2/A6, B_

### ⚠️  WARN — Sicherheits-Header (HSTS, nosniff)

Fehlende Sicherheits-Header: X-Content-Type-Options: nosniff.

**Remediation:** Über HTTPS 'Strict-Transport-Security: max-age=15552000; includeSubDomains' setzen und 'X-Content-Type-Options: nosniff' senden.

_Reference: MCP Security Checklist #15_

### ⚠️  WARN — Session-ID Unvorhersagbarkeit (mcp-session-id)

Ausgegebene 'mcp-session-id' (test…, 12 Zeichen) wirkt schwach: zu kurz (12 Zeichen, < 16). Ratbar/erzwingbar → Risiko Session-Hijacking.

**Remediation:** Kryptographisch sichere Session-IDs verwenden (CSPRNG, ≥128 Bit Entropie, z. B. crypto.randomUUID); nicht sequentiell oder aus Klartext ableiten.

_Reference: MCP Security Checklist Session-Hijacking_

### ⚠️  WARN — OAuth 2.1 Metadaten & PKCE (S256)

Keine OAuth-Authorization-Server-Metadaten unter den Standard-.well-known-Pfaden gefunden. Entweder kein OAuth (bei Remote-Servern problematisch) oder abweichender Discovery-Pfad.

**Remediation:** Für Remote-MCP OAuth 2.1 mit veröffentlichten Metadaten (RFC 8414/9728) bereitstellen.

_Reference: MCP Security Checklist A1/A2/A6, B_

### ⚠️  WARN — Origin-Header-Validierung (DNS-Rebinding)

Server akzeptiert 'initialize' mit fremdem Origin (https://dns-rebind.attacker.example, HTTP 200) ohne Abweisung. Die MCP-Streamable-HTTP-Spezifikation verlangt Origin-Validierung gegen DNS-Rebinding — besonders kritisch bei lokal oder im internen Netz erreichbaren Servern.

**Remediation:** Origin-Header gegen feste Allowlist prüfen und fremde Origins mit 403 ablehnen; Server nur an benötigte Interfaces binden.

_Reference: MCP Security Checklist #15_

### ⚠️  WARN — Rate-Limiting (Burst-Heuristik)

Burst von 12 Requests ohne einzige 429-Antwort. Kein von außen erkennbares Rate-Limiting (Heuristik — evtl. höhere Schwelle).

**Remediation:** Rate-Limits pro Tenant/Client/Tool und Budget-Caps für teure Operationen einführen.

_Reference: MCP Security Checklist #12 Rate-Limiting_

### ℹ️  INFO — Authentifizierung erzwungen

Server antwortet auf 'initialize' ohne Token (HTTP 200). Für sich genommen unkritisch — entscheidend ist, ob Tool-Aufrufe ohne Token möglich sind (siehe Check 'unauth-tools').

_Reference: MCP Security Checklist A1/A2/A6, B_

### ℹ️  INFO — Protected Resource Metadata (RFC 9728) & Audience-Bindung

Keine RFC-9728-Protected-Resource-Metadaten gefunden. Bei einem tokengeschützten Remote-MCP-Server per Spec erwartet — hier wird aber keine Auth erzwungen, daher nur informativ.

**Remediation:** Falls OAuth-geschützt: RFC-9728-Metadaten (resource + authorization_servers) veröffentlichen.

_Reference: MCP Security Checklist A2/A6 (Token-Audience, RFC 8707/9728)_

---

> This is an **external** scan without write access — but **not purely observational**: it performs an unauthenticated MCP handshake, attempts `tools/list`, deliberately provokes an error response and sends a request with a foreign `Origin` header. It does not prove the absence of internal issues (tenant isolation, audit logging, injection handling in tool parameters). A full audit adds those. Scan only servers you own or are explicitly authorised to test.
