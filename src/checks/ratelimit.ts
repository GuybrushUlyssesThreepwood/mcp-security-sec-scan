// Rate-Limiting-Heuristik (aktiver, aber zerstörungsfreier Probe).
// Nur wenn --active gesetzt ist: kleiner Burst harmloser 'initialize'-Requests.

import type { Check, Finding, ScanContext } from "../types.js";
import { initializeParams, jsonRpc, postRpc } from "../probe.js";

const REF = "MCP Security Checklist #12 Rate-Limiting";
const BURST = 12;

export const rateLimiting: Check = {
  id: "rate-limiting",
  title: "Rate-Limiting (Burst-Heuristik)",
  async run(ctx: ScanContext): Promise<Finding[]> {
    if (!ctx.activeProbes) {
      return [{
        id: this.id, title: this.title, severity: "skipped",
        detail: "Übersprungen (aktive Probes aus). Mit --active einen kleinen Burst senden, um 429/Drosselung zu prüfen.",
        reference: REF,
      }];
    }

    const results = await Promise.all(
      Array.from({ length: BURST }, () =>
        postRpc(ctx.url, jsonRpc("initialize", initializeParams()), { timeoutMs: ctx.timeoutMs, token: ctx.token })
      )
    );
    const throttled = results.filter((r) => r.status === 429).length;
    const retryAfter = results.find((r) => r.headers["retry-after"])?.headers["retry-after"];

    if (throttled > 0) {
      return [{
        id: this.id, title: this.title, severity: "pass",
        detail: `Burst von ${BURST} Requests: ${throttled}× HTTP 429${retryAfter ? ` (Retry-After: ${retryAfter})` : ""}. Drosselung aktiv.`,
        reference: REF,
      }];
    }
    return [{
      id: this.id, title: this.title, severity: "warn",
      detail: `Burst von ${BURST} Requests ohne einzige 429-Antwort. Kein von außen erkennbares Rate-Limiting (Heuristik — evtl. höhere Schwelle).`,
      remediation: "Rate-Limits pro Tenant/Client/Tool und Budget-Caps für teure Operationen einführen.",
      reference: REF,
    }];
  },
};
