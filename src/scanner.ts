// Orchestriert alle Checks und aggregiert das Ergebnis.

import { CHECKS } from "./checks/index.js";
import type { Finding, ScanContext, ScanReport, Severity, SharedState } from "./types.js";
export { SCANNER_VERSION } from "./version.js";
import { SCANNER_VERSION } from "./version.js";

const PASSIVE_SKIP_DETAIL =
  "Übersprungen im Beobachtungsmodus (--passive). Dieser Check sendet Anfragen an den " +
  "MCP-Endpunkt selbst (JSON-RPC-Handshake, Tool-Auflistung, provozierte Fehler oder Burst) " +
  "und läuft deshalb nur mit dokumentierter Erlaubnis des Betreibers.";

export async function runScan(ctx: ScanContext): Promise<ScanReport> {
  const shared: SharedState = {};
  const findings: Finding[] = [];

  for (const check of CHECKS) {
    // Beobachtungsmodus: alles überspringen, was den Endpunkt selbst anspricht. Bewusst als
    // 'skipped' im Report statt stiller Auslassung — der Leser muss sehen, was NICHT geprüft wurde.
    if (ctx.passive && !check.passiveSafe) {
      findings.push({
        id: check.id,
        title: check.title,
        severity: "skipped",
        detail: PASSIVE_SKIP_DETAIL,
        remediation: "Mit Auftrag und dokumentierter Erlaubnis ohne --passive erneut scannen.",
      });
      continue;
    }
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
    mode: ctx.passive ? "passive" : "standard",
    findings,
    summary,
  };
}
