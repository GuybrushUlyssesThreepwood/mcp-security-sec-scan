// Rate-limiting heuristic (an active but non-destructive probe).
// Only when --active is set: a small burst of harmless 'initialize' requests.

import type { Check, Finding, ScanContext } from "../types.js";
import { initializeParams, jsonRpc, postRpc } from "../probe.js";

const REF = "MCP Security Checklist #12 Rate-Limiting";
const BURST = 12;

export const rateLimiting: Check = {
  id: "rate-limiting",
  title: "Rate limiting (burst heuristic)",
  async run(ctx: ScanContext): Promise<Finding[]> {
    if (!ctx.activeProbes) {
      return [{
        id: this.id, title: this.title, severity: "skipped",
        detail: "Skipped (active probes off). Use --active to send a small burst and test for 429/throttling.",
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
        detail: `Burst of ${BURST} requests: ${throttled}x HTTP 429${retryAfter ? ` (Retry-After: ${retryAfter})` : ""}. Throttling is active.`,
        reference: REF,
      }];
    }
    return [{
      id: this.id, title: this.title, severity: "warn",
      detail: `Burst of ${BURST} requests without a single 429 response. No externally detectable rate limiting (heuristic — the threshold may simply be higher).`,
      remediation: "Introduce rate limits per tenant/client/tool and budget caps for expensive operations.",
      reference: REF,
    }];
  },
};
