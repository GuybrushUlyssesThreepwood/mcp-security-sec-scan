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
  md.push(`**Scanner:** mcp-sec-scan v${report.scannerVersion}`);
  md.push("");
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
  md.push(`> This is an **external, non-invasive** scan: it only observes what the server exposes without a valid token or with a token you provided. It does not prove the absence of internal issues (tenant isolation, audit logging, injection handling in tool parameters). A full audit adds those. Scan only servers you own or are explicitly authorized to test.`);
  md.push("");
  return md.join("\n");
}

/** Exit-Code: 2 bei mindestens einem Problem, 1 bei nur Warnungen, sonst 0. Für CI-Gates. */
export function exitCode(report: ScanReport): number {
  if (report.summary.problem > 0) return 2;
  if (report.summary.warn > 0) return 1;
  return 0;
}
