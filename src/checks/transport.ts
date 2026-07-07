// Transport-/CORS-Checks: TLS-Erzwingung, CORS, Origin-Validierung und Sicherheits-Header.

import type { Check, Finding, ScanContext, SharedState } from "../types.js";
import { getUrl, postRpc, jsonRpc, initializeParams } from "../probe.js";

const REF = "MCP Security Checklist #15 (T-003)";

function safeProtocol(url: string): string {
  try {
    return new URL(url).protocol;
  } catch {
    return "";
  }
}

export const tlsEnforced: Check = {
  id: "tls-enforced",
  title: "TLS erzwungen (kein Klartext-HTTP)",
  async run(ctx: ScanContext): Promise<Finding[]> {
    let proto = "";
    try {
      proto = new URL(ctx.url).protocol;
    } catch {
      return [{ id: this.id, title: this.title, severity: "info", detail: "URL nicht parsebar.", reference: REF }];
    }
    if (proto === "https:") {
      return [{
        id: this.id, title: this.title, severity: "pass",
        detail: "Endpoint wird über HTTPS angesprochen.",
        reference: REF,
      }];
    }
    return [{
      id: this.id, title: this.title, severity: "problem",
      detail: `Endpoint nutzt '${proto}' statt HTTPS. Tokens/Daten wären im Klartext übertragbar.`,
      remediation: "Remote-MCP ausschließlich über HTTPS; HTTP auf HTTPS umleiten oder ablehnen.",
      reference: REF,
    }];
  },
};

export const corsConfig: Check = {
  id: "cors-config",
  title: "CORS-Konfiguration",
  async run(ctx: ScanContext): Promise<Finding[]> {
    // Mit fremdem Origin anfragen und Reflection/Wildcard prüfen.
    const evilOrigin = "https://mcp-sec-scan.example.attacker";
    const probe = await getUrl(ctx.url, ctx.timeoutMs, evilOrigin);
    const acao = probe.headers["access-control-allow-origin"];
    const acac = probe.headers["access-control-allow-credentials"];

    if (!acao) {
      return [{
        id: this.id, title: this.title, severity: "pass",
        detail: "Kein Access-Control-Allow-Origin für fremden Origin gesetzt (Browser-Cross-Origin blockiert).",
        reference: REF,
      }];
    }
    if (acao === "*" && acac === "true") {
      return [{
        id: this.id, title: this.title, severity: "problem",
        detail: "ACAO '*' zusammen mit Allow-Credentials 'true' — unsichere Kombination (Credentials für jeden Origin).",
        remediation: "Keine Wildcard mit Credentials. Origin-Allowlist verwenden.",
        reference: REF,
      }];
    }
    if (acao === evilOrigin) {
      return [{
        id: this.id, title: this.title, severity: "warn",
        detail: `Server spiegelt beliebigen Origin (${evilOrigin}) in ACAO wider — faktisch offenes CORS.`,
        remediation: "Origin gegen feste Allowlist prüfen statt zu spiegeln.",
        reference: REF,
      }];
    }
    if (acao === "*") {
      return [{
        id: this.id, title: this.title, severity: "warn",
        detail: "ACAO '*' (offenes CORS ohne Credentials). Bei rein tokenbasiertem Zugriff meist ok, aber bewusst setzen.",
        reference: REF,
      }];
    }
    return [{
      id: this.id, title: this.title, severity: "info",
      detail: `ACAO gesetzt auf '${acao}'.`,
      reference: REF,
    }];
  },
};

export const originValidation: Check = {
  id: "origin-validation",
  title: "Origin-Header-Validierung (DNS-Rebinding)",
  async run(ctx: ScanContext): Promise<Finding[]> {
    // MCP Streamable HTTP: Server MÜSSEN den Origin-Header validieren, um DNS-Rebinding
    // zu verhindern. Wir senden 'initialize' mit fremdem Origin und prüfen, ob abgewiesen wird.
    const evilOrigin = "https://dns-rebind.attacker.example";
    const probe = await postRpc(ctx.url, jsonRpc("initialize", initializeParams()), {
      timeoutMs: ctx.timeoutMs,
      token: ctx.token,
      extraHeaders: { origin: evilOrigin },
    });

    if (probe.error) {
      return [{
        id: this.id, title: this.title, severity: "info",
        detail: `Kein Ergebnis (Netzwerk/Timeout): ${probe.error}`,
        reference: REF,
      }];
    }
    if (probe.status === 400 || probe.status === 403) {
      return [{
        id: this.id, title: this.title, severity: "pass",
        detail: `Anfrage mit fremdem Origin (${evilOrigin}) abgewiesen (HTTP ${probe.status}).`,
        reference: REF,
      }];
    }
    if (probe.status === 401) {
      return [{
        id: this.id, title: this.title, severity: "info",
        detail: `Auth wird vor der Origin-Prüfung erzwungen (HTTP 401) — Origin-Validierung ist von außen nicht eindeutig prüfbar.`,
        remediation: "Sicherstellen, dass der Origin serverseitig gegen eine Allowlist geprüft wird (auch für authentifizierte Anfragen).",
        reference: REF,
      }];
    }
    if (probe.status >= 200 && probe.status < 300) {
      return [{
        id: this.id, title: this.title, severity: "warn",
        detail: `Server akzeptiert 'initialize' mit fremdem Origin (${evilOrigin}, HTTP ${probe.status}) ohne Abweisung. Die MCP-Streamable-HTTP-Spezifikation verlangt Origin-Validierung gegen DNS-Rebinding — besonders kritisch bei lokal oder im internen Netz erreichbaren Servern.`,
        remediation: "Origin-Header gegen feste Allowlist prüfen und fremde Origins mit 403 ablehnen; Server nur an benötigte Interfaces binden.",
        reference: REF,
      }];
    }
    return [{
      id: this.id, title: this.title, severity: "info",
      detail: `Unerwarteter Status auf 'initialize' mit fremdem Origin: HTTP ${probe.status}.`,
      reference: REF,
    }];
  },
};

export const securityHeaders: Check = {
  id: "security-headers",
  title: "Sicherheits-Header (HSTS, nosniff)",
  async run(ctx: ScanContext, shared: SharedState): Promise<Finding[]> {
    // Wiederverwenden, was 'auth-required' bereits ermittelt hat; sonst selbst einmal proben.
    let headers = shared.unauthInitialize?.headers;
    if (!headers) {
      const probe = await postRpc(ctx.url, jsonRpc("initialize", initializeParams()), {
        timeoutMs: ctx.timeoutMs,
        token: ctx.token,
      });
      shared.unauthInitialize = probe;
      headers = probe.headers;
    }
    if (!headers || Object.keys(headers).length === 0) {
      return [{
        id: this.id, title: this.title, severity: "info",
        detail: "Keine Antwort-Header ermittelbar (Server nicht erreichbar?).",
        reference: REF,
      }];
    }

    const isHttps = safeProtocol(ctx.url) === "https:";
    const missing: string[] = [];
    if (isHttps && !headers["strict-transport-security"]) missing.push("Strict-Transport-Security (HSTS)");
    if (!headers["x-content-type-options"]) missing.push("X-Content-Type-Options: nosniff");

    if (missing.length === 0) {
      return [{
        id: this.id, title: this.title, severity: "pass",
        detail: `Sicherheits-Header vorhanden${isHttps ? " (inkl. HSTS)" : ""}.`,
        reference: REF,
      }];
    }
    return [{
      id: this.id, title: this.title, severity: "warn",
      detail: `Fehlende Sicherheits-Header: ${missing.join(", ")}.`,
      remediation: "Über HTTPS 'Strict-Transport-Security: max-age=15552000; includeSubDomains' setzen und 'X-Content-Type-Options: nosniff' senden.",
      reference: REF,
    }];
  },
};
