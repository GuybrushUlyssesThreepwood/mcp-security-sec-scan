// Tool-related checks: unauthenticated tool listing/invocation and the tool-poisoning heuristic.

import type { Check, Finding, McpTool, ScanContext, SharedState } from "../types.js";
import { initializeParams, jsonRpc, postRpc } from "../probe.js";

const REF_UNAUTH = "MCP Security Checklist #1";
const REF_POISON = "MCP Security Checklist #9 Tool Poisoning";

/** MCP handshake, only as far as needed to attempt tools/list. */
async function listTools(
  ctx: ScanContext,
  withToken: boolean
): Promise<{ status: number; tools?: McpTool[]; rpcError?: { code?: number; message?: string }; error?: string }> {
  const token = withToken ? ctx.token : undefined;
  const init = await postRpc(ctx.url, jsonRpc("initialize", initializeParams()), { timeoutMs: ctx.timeoutMs, token });
  if (init.error) return { status: 0, error: init.error };
  if (init.status < 200 || init.status >= 300) return { status: init.status };

  const sessionId = init.headers["mcp-session-id"];

  // Send the 'initialized' notification (no id) — some servers require it before further calls.
  await postRpc(ctx.url, { jsonrpc: "2.0", method: "notifications/initialized", params: {} }, { timeoutMs: ctx.timeoutMs, token, sessionId });

  const list = await postRpc(ctx.url, jsonRpc("tools/list", {}, 2), { timeoutMs: ctx.timeoutMs, token, sessionId });
  if (list.status < 200 || list.status >= 300) return { status: list.status };

  // JSON-RPC carries application errors over HTTP 200 with an 'error' object (JSON-RPC 2.0 §5.1).
  // A server that correctly refuses an unauthenticated tools/list that way has NOT delivered —
  // reading that as success was a false positive of the highest severity.
  const body = list.json as { result?: { tools?: McpTool[] }; error?: { code?: number; message?: string } } | undefined;
  if (body?.error) return { status: list.status, rpcError: body.error };

  // No 'result' in the body = no usable response. Do not report it as an empty tool list.
  if (!body?.result || !Array.isArray(body.result.tools)) return { status: list.status };

  return { status: list.status, tools: body.result.tools };
}

export const unauthTools: Check = {
  id: "unauth-tools",
  title: "Tool listing without authentication",
  async run(ctx: ScanContext, shared: SharedState): Promise<Finding[]> {
    const res = await listTools(ctx, false);

    if (res.tools && res.tools.length > 0) {
      // Remember them for later checks (poisoning) if we do not know them otherwise.
      if (!shared.tools) shared.tools = res.tools;
      return [{
        id: this.id, title: this.title, severity: "problem",
        detail: `tools/list without a token succeeded (${res.tools.length} tools visible). The server requires no auth for tool use.`,
        remediation: "Enforce OAuth 2.1 for all tool operations; reject unauthenticated requests with 401.",
        reference: REF_UNAUTH,
      }];
    }
    if (res.tools) {
      // The response was formally successful but carried no tools. Not an auth finding.
      if (!shared.tools) shared.tools = res.tools;
      return [{
        id: this.id, title: this.title, severity: "info",
        detail: "tools/list without a token returns an empty tool list. No unauthenticated tool access demonstrated — the server simply offers no tools here.",
        reference: REF_UNAUTH,
      }];
    }
    if (res.rpcError) {
      // A refusal via JSON-RPC error over HTTP 200 is spec-compliant and counts as a refusal.
      return [{
        id: this.id, title: this.title, severity: "pass",
        detail: `tools/list without a token was refused (JSON-RPC error ${res.rpcError.code ?? "?"}: ${res.rpcError.message ?? "no message"}, HTTP ${res.status}).`,
        reference: REF_UNAUTH,
      }];
    }
    if (res.status === 401 || res.status === 403) {
      return [{
        id: this.id, title: this.title, severity: "pass",
        detail: `tools/list without a token was refused (HTTP ${res.status}).`,
        reference: REF_UNAUTH,
      }];
    }
    return [{
      id: this.id, title: this.title, severity: "info",
      detail: res.error ? `Could not complete tools/list: ${res.error}` : `tools/list without a token did not succeed (HTTP ${res.status}) — auth is probably required, but not unambiguously signalled as 401.`,
      reference: REF_UNAUTH,
    }];
  },
};

const POISON_PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /ignore\s+(all\s+)?previous|disregard\s+(the\s+)?above/i, label: "instruction-override" },
  { re: /<\s*(system|important|secret)\s*>/i, label: "hidden pseudo-tags" },
  { re: /\b(system\s*:|assistant\s*:)/i, label: "role injection" },
  { re: /do\s+not\s+(tell|inform|mention).*(user|owner)/i, label: "concealment instruction" },
  { re: /(exfiltrat|send\s+.*to\s+https?:\/\/|curl\s+https?:\/\/)/i, label: "exfiltration hint" },
  // Deliberately narrow: a tool that legitimately takes a password (login, vault, DB connect)
  // is not a poisoning finding. Only references to foreign secret files or stores count.
  { re: /(\.env\b|id_rsa|~\/\.ssh|\.aws\/credentials|aws_secret_access_key|\.git-credentials)/i, label: "secret path" },
  { re: /[​-‏‪-‮⁠]/, label: "invisible/control unicode" },
];

export const toolPoisoning: Check = {
  id: "tool-poisoning",
  title: "Tool poisoning heuristic",
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
        detail: "No tool list reachable (auth required, no valid token supplied). Pass --token for the deep check.",
        reference: REF_POISON,
      }];
    }
    if (tools.length === 0) {
      return [{ id: this.id, title: this.title, severity: "info", detail: "The server offers 0 tools.", reference: REF_POISON }];
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
        detail: `Suspicious patterns in ${flagged.length} tool description(s):\n  - ${flagged.join("\n  - ")}`,
        remediation: "Curate and sanitise tool metadata; version descriptions (rug-pull protection); mark untrusted content.",
        reference: REF_POISON,
      }];
    }
    return [{
      id: this.id, title: this.title, severity: "pass",
      detail: `Checked ${tools.length} tool descriptions, found no suspicious injection patterns.`,
      reference: REF_POISON,
    }];
  },
};
