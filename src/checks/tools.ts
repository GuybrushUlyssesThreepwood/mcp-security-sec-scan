// Tool-bezogene Checks: unauthentifizierte Tool-Auflistung/-Aufruf und Tool-Poisoning-Heuristik.

import type { Check, Finding, McpTool, ScanContext, SharedState } from "../types.js";
import { initializeParams, jsonRpc, postRpc } from "../probe.js";

const REF_UNAUTH = "MCP Security Checklist #1 (T-003)";
const REF_POISON = "MCP Security Checklist #9 Tool Poisoning (T-003)";

/** MCP-Handshake so weit wie nötig, um tools/list zu versuchen. */
async function listTools(ctx: ScanContext, withToken: boolean): Promise<{ status: number; tools?: McpTool[]; error?: string }> {
  const token = withToken ? ctx.token : undefined;
  const init = await postRpc(ctx.url, jsonRpc("initialize", initializeParams()), { timeoutMs: ctx.timeoutMs, token });
  if (init.error) return { status: 0, error: init.error };
  if (init.status < 200 || init.status >= 300) return { status: init.status };

  const sessionId = init.headers["mcp-session-id"];

  // 'initialized'-Notification (ohne id) senden — manche Server verlangen sie vor weiteren Calls.
  await postRpc(ctx.url, { jsonrpc: "2.0", method: "notifications/initialized", params: {} }, { timeoutMs: ctx.timeoutMs, token, sessionId });

  const list = await postRpc(ctx.url, jsonRpc("tools/list", {}, 2), { timeoutMs: ctx.timeoutMs, token, sessionId });
  if (list.status < 200 || list.status >= 300) return { status: list.status };

  const result = (list.json as { result?: { tools?: McpTool[] } })?.result;
  return { status: list.status, tools: result?.tools ?? [] };
}

export const unauthTools: Check = {
  id: "unauth-tools",
  title: "Tool-Auflistung ohne Authentifizierung",
  async run(ctx: ScanContext, shared: SharedState): Promise<Finding[]> {
    const res = await listTools(ctx, false);

    if (res.tools) {
      // Für spätere Checks (Poisoning) merken, wenn wir sie sonst nicht kennen.
      if (!shared.tools) shared.tools = res.tools;
      return [{
        id: this.id, title: this.title, severity: "problem",
        detail: `tools/list ohne Token erfolgreich (${res.tools.length} Tools sichtbar). Der Server verlangt keine Authentifizierung für die Tool-Nutzung.`,
        remediation: "OAuth 2.1 für alle Tool-Operationen erzwingen; unauthentifizierte Requests mit 401 abweisen.",
        reference: REF_UNAUTH,
      }];
    }
    if (res.status === 401 || res.status === 403) {
      return [{
        id: this.id, title: this.title, severity: "pass",
        detail: `tools/list ohne Token abgewiesen (HTTP ${res.status}).`,
        reference: REF_UNAUTH,
      }];
    }
    return [{
      id: this.id, title: this.title, severity: "info",
      detail: res.error ? `Konnte tools/list nicht abschließen: ${res.error}` : `tools/list ohne Token nicht erfolgreich (HTTP ${res.status}) — vermutlich Auth erforderlich, aber nicht eindeutig als 401.`,
      reference: REF_UNAUTH,
    }];
  },
};

const POISON_PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /ignore\s+(all\s+)?previous|disregard\s+(the\s+)?above/i, label: "Instruktions-Override" },
  { re: /<\s*(system|important|secret)\s*>/i, label: "versteckte Pseudo-Tags" },
  { re: /\b(system\s*:|assistant\s*:)/i, label: "Rollen-Injektion" },
  { re: /do\s+not\s+(tell|inform|mention).*(user|owner)/i, label: "Verschleierungs-Anweisung" },
  { re: /(exfiltrat|send\s+.*to\s+https?:\/\/|curl\s+https?:\/\/)/i, label: "Exfiltrations-Hinweis" },
  { re: /(\.env|id_rsa|~\/\.ssh|aws_secret|password)/i, label: "Secret-/Dateipfad-Referenz" },
  { re: /[​-‏‪-‮⁠]/, label: "unsichtbare/Steuer-Unicode-Zeichen" },
];

export const toolPoisoning: Check = {
  id: "tool-poisoning",
  title: "Tool-Poisoning-Heuristik (Beschreibungen)",
  async run(ctx: ScanContext, shared: SharedState): Promise<Finding[]> {
    let tools = shared.tools;
    if (!tools && ctx.token) {
      const res = await listTools(ctx, true);
      tools = res.tools;
      if (tools) shared.tools = tools;
    }
    if (!tools) {
      return [{
        id: this.id, title: this.title, severity: "skipped",
        detail: "Keine Tool-Liste erreichbar (Auth nötig, kein/kein gültiges Token übergeben). Für Tiefencheck --token setzen.",
        reference: REF_POISON,
      }];
    }
    if (tools.length === 0) {
      return [{ id: this.id, title: this.title, severity: "info", detail: "Server bietet 0 Tools an.", reference: REF_POISON }];
    }

    const flagged: string[] = [];
    for (const t of tools) {
      const text = `${t.name ?? ""} ${t.description ?? ""} ${JSON.stringify(t.inputSchema ?? {})}`;
      const hits = POISON_PATTERNS.filter((p) => p.re.test(text)).map((p) => p.label);
      if (hits.length) flagged.push(`${t.name}: ${hits.join(", ")}`);
    }

    if (flagged.length) {
      return [{
        id: this.id, title: this.title, severity: "problem",
        detail: `Verdächtige Muster in ${flagged.length} Tool-Beschreibung(en):\n  - ${flagged.join("\n  - ")}`,
        remediation: "Tool-Metadaten kuratieren/sanitizen; Beschreibungen versionieren (Rug-Pull-Schutz); untrusted content markieren.",
        reference: REF_POISON,
      }];
    }
    return [{
      id: this.id, title: this.title, severity: "pass",
      detail: `${tools.length} Tool-Beschreibungen geprüft, keine verdächtigen Injektions-Muster gefunden.`,
      reference: REF_POISON,
    }];
  },
};
