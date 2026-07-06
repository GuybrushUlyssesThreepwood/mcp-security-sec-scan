// Transport-/CORS-Checks: TLS-Erzwingung und CORS-Konfiguration.

import type { Check, Finding, ScanContext } from "../types.js";
import { getUrl } from "../probe.js";

const REF = "MCP Security Checklist #15 (T-003)";

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
