// Orchestriert alle Checks und aggregiert das Ergebnis.

import { CHECKS } from "./checks/index.js";
import type { Finding, ScanContext, ScanReport, Severity, SharedState } from "./types.js";

export const SCANNER_VERSION = "1.0.0";

export async function runScan(ctx: ScanContext): Promise<ScanReport> {
  const shared: SharedState = {};
  const findings: Finding[] = [];

  for (const check of CHECKS) {
    try {
      const res = await check.run(ctx, shared);
      findings.push(...res);
    } catch (err) {
      findings.push({
        id: check.id,
        title: check.title,
        severity: "info",
        detail: `Check-Fehler: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }

  const summary: Record<Severity, number> = { pass: 0, info: 0, warn: 0, problem: 0, skipped: 0 };
  for (const f of findings) summary[f.severity]++;

  return {
    target: ctx.url,
    scannedAt: new Date().toISOString(),
    scannerVersion: SCANNER_VERSION,
    findings,
    summary,
  };
}
