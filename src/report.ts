// Report-Ausgabe: farbiges Terminal + Markdown-Export (Kunden-tauglich).

import type { Finding, ScanReport, Severity } from "./types.js";

const ICON: Record<Severity, string> = {
  pass: "✅",
  info: "ℹ️ ",
  warn: "⚠️ ",
  problem: "❌",
  skipped: "⏭️ ",
};

const LABEL: Record<Severity, string> = {
  pass: "PASS",
  info: "INFO",
  warn: "WARN",
  problem: "PROBLEM",
  skipped: "SKIPPED",
};

const COLOR: Record<Severity, string> = {
  pass: "\x1b[32m",
  info: "\x1b[36m",
  warn: "\x1b[33m",
  problem: "\x1b[31m",
  skipped: "\x1b[90m",
};
const RESET = "\x1b[0m";

const ORDER: Severity[] = ["problem", "warn", "pass", "info", "skipped"];

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity));
}

export function toTerminal(report: ScanReport, color = true): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(`mcp-sec-scan v${report.scannerVersion}`);
  lines.push(`Target : ${report.target}`);
  lines.push(`Scanned: ${report.scannedAt}`);
  lines.push(
    report.mode === "passive"
      ? "Mode   : passive (observation only — no requests to the MCP endpoint itself)"
      : "Mode   : standard (external scan — includes an unauthenticated handshake)"
  );
  lines.push("");
  for (const f of sortFindings(report.findings)) {
    const c = color ? COLOR[f.severity] : "";
    const r = color ? RESET : "";
    lines.push(`${ICON[f.severity]} ${c}${LABEL[f.severity].padEnd(7)}${r} ${f.title}`);
    for (const dl of f.detail.split("\n")) lines.push(`    ${dl}`);
    if (f.remediation) lines.push(`    → Fix: ${f.remediation}`);
  }
  lines.push("");
  const s = report.summary;
  lines.push(`Summary: ${s.problem} problem · ${s.warn} warn · ${s.pass} pass · ${s.info} info · ${s.skipped} skipped`);
  lines.push("");
  return lines.join("\n");
}

export function toMarkdown(report: ScanReport): string {
  const s = report.summary;
  const md: string[] = [];
  md.push(`# MCP Security Scan Report`);
  md.push("");
  md.push(`**Target:** \`${report.target}\`  `);
  md.push(`**Scanned:** ${report.scannedAt}  `);
  md.push(`**Scanner:** mcp-sec-scan v${report.scannerVersion}  `);
  md.push(`**Mode:** ${report.mode === "passive" ? "passive (observation only)" : "standard (external scan)"}`);
  md.push("");
  if (report.mode === "passive") {
    md.push(
      "> **Beobachtungsmodus.** Es wurde keine Anfrage an den MCP-Endpunkt selbst gesendet — " +
        "geprüft wurden ausschließlich die URL und die standardisierten `.well-known`-Discovery-Pfade " +
        "(RFC 8414 / RFC 9728), die dafür veröffentlicht werden, unauthentifiziert abgerufen zu werden. " +
        "Kein Handshake, keine Tool-Auflistung, keine provozierten Fehler, kein Burst. " +
        "**Ein sauberes Ergebnis in diesem Modus sagt nichts über die Auth-Durchsetzung des Servers aus** — " +
        "dafür braucht es einen vollständigen Scan mit Erlaubnis des Betreibers."
    );
    md.push("");
  }
  md.push(`## Summary`);
  md.push("");
  md.push(`| Severity | Count |`);
  md.push(`|----------|------:|`);
  md.push(`| ❌ Problem | ${s.problem} |`);
  md.push(`| ⚠️ Warn | ${s.warn} |`);
  md.push(`| ✅ Pass | ${s.pass} |`);
  md.push(`| ℹ️ Info | ${s.info} |`);
  md.push(`| ⏭️ Skipped | ${s.skipped} |`);
  md.push("");
  md.push(`## Findings`);
  md.push("");
  for (const f of sortFindings(report.findings)) {
    md.push(`### ${ICON[f.severity]} ${LABEL[f.severity]} — ${f.title}`);
    md.push("");
    md.push(f.detail.split("\n").map((l) => l.trim()).join("  \n"));
    md.push("");
    if (f.remediation) {
      md.push(`**Remediation:** ${f.remediation}`);
      md.push("");
    }
    if (f.reference) {
      md.push(`_Reference: ${f.reference}_`);
      md.push("");
    }
  }
  md.push(`---`);
  md.push("");
  md.push(
    report.mode === "passive"
      ? `> This was an **observation-only** run: no request reached the MCP endpoint itself, only the standardised \`.well-known\` discovery paths. It proves nothing about the server's auth enforcement, and nothing about internal issues (tenant isolation, audit logging, injection handling in tool parameters). Scan only servers you own or are explicitly authorised to test.`
      : `> This is an **external** scan without write access — but **not purely observational**: it performs an unauthenticated MCP handshake, attempts \`tools/list\`, deliberately provokes an error response and sends a request with a foreign \`Origin\` header. It does not prove the absence of internal issues (tenant isolation, audit logging, injection handling in tool parameters). A full audit adds those. Scan only servers you own or are explicitly authorised to test.`
  );
  md.push("");
  return md.join("\n");
}

const REPO_URL = "https://github.com/GuybrushUlyssesThreepwood/mcp-security-sec-scan";

/** SARIF-Schweregrad: problem→error, warn→warning, sonst note. */
function sarifLevel(sev: Severity): "error" | "warning" | "note" {
  if (sev === "problem") return "error";
  if (sev === "warn") return "warning";
  return "note";
}

/**
 * SARIF 2.1.0 für GitHub Code Scanning (Security-Tab). pass/skipped werden
 * ausgelassen — nur echte Findings (problem/warn/info) werden als Results emittiert.
 */
export function toSarif(report: ScanReport): unknown {
  const emitted = report.findings.filter((f) => f.severity !== "pass" && f.severity !== "skipped");

  // Regeln aus den vorkommenden Check-IDs (dedupliziert).
  const ruleById = new Map<string, Finding>();
  for (const f of emitted) if (!ruleById.has(f.id)) ruleById.set(f.id, f);
  const rules = [...ruleById.values()].map((f) => ({
    id: f.id,
    name: f.title,
    shortDescription: { text: f.title },
    fullDescription: { text: f.remediation ? `${f.title}. ${f.remediation}` : f.title },
    helpUri: REPO_URL,
    help: { text: f.remediation ?? f.detail },
    defaultConfiguration: { level: sarifLevel(f.severity) },
    ...(f.reference ? { properties: { reference: f.reference } } : {}),
  }));

  const results = emitted.map((f) => ({
    ruleId: f.id,
    level: sarifLevel(f.severity),
    message: { text: f.remediation ? `${f.detail}\n\nRemediation: ${f.remediation}` : f.detail },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: report.target },
          region: { startLine: 1 },
        },
      },
    ],
    partialFingerprints: { checkId: f.id },
  }));

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-sec-scan",
            informationUri: REPO_URL,
            version: report.scannerVersion,
            rules,
          },
        },
        results,
        invocations: [{ executionSuccessful: true, endTimeUtc: report.scannedAt }],
        properties: { target: report.target, summary: report.summary },
      },
    ],
  };
}

/** Exit-Code: 2 bei mindestens einem Problem, 1 bei nur Warnungen, sonst 0. Für CI-Gates. */
export function exitCode(report: ScanReport): number {
  if (report.summary.problem > 0) return 2;
  if (report.summary.warn > 0) return 1;
  return 0;
}
