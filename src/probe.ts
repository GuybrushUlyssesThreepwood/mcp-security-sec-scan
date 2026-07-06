// Low-level HTTP-Probing für MCP Streamable HTTP Endpunkte.
// Bewusst SDK-unabhängig: Wir wollen rohe Statuscodes/Header/Bodies sehen (401, WWW-Authenticate,
// CORS, Fehler-Verbosity) — genau das prüft ein externer Security-Scan.

import type { ProbeResult } from "./types.js";

const SCANNER_VERSION = "1.0.0";
export const CLIENT_PROTOCOL_VERSION = "2025-06-18";

export function jsonRpc(method: string, params: unknown, id: number | string = 1) {
  return { jsonrpc: "2.0", id, method, params };
}

export function initializeParams() {
  return {
    protocolVersion: CLIENT_PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name: "mcp-sec-scan", version: SCANNER_VERSION },
  };
}

function headersToObject(h: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  h.forEach((v, k) => {
    out[k.toLowerCase()] = v;
  });
  return out;
}

/** SSE-Antworten (text/event-stream) auf das erste JSON-RPC-data-Frame reduzieren. */
function parseMaybeSse(contentType: string, text: string): unknown {
  if (contentType.includes("text/event-stream")) {
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (trimmed.startsWith("data:")) {
        const payload = trimmed.slice(5).trim();
        if (!payload || payload === "[DONE]") continue;
        try {
          return JSON.parse(payload);
        } catch {
          /* nächstes Frame versuchen */
        }
      }
    }
    return undefined;
  }
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

export interface PostOptions {
  token?: string;
  timeoutMs: number;
  sessionId?: string;
  extraHeaders?: Record<string, string>;
}

/** Ein JSON-RPC-POST gegen den Endpunkt. Wirft nie — Fehler landen in ProbeResult.error. */
export async function postRpc(
  url: string,
  body: unknown,
  opts: PostOptions
): Promise<ProbeResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs);
  try {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...(opts.extraHeaders ?? {}),
    };
    if (opts.token) headers["authorization"] = `Bearer ${opts.token}`;
    if (opts.sessionId) headers["mcp-session-id"] = opts.sessionId;

    const res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
      redirect: "manual",
    });
    const text = await res.text();
    const ct = res.headers.get("content-type") ?? "";
    return {
      status: res.status,
      ok: res.ok,
      headers: headersToObject(res.headers),
      json: parseMaybeSse(ct, text),
      text: text.slice(0, 4000),
    };
  } catch (err) {
    return {
      status: 0,
      ok: false,
      headers: {},
      error: err instanceof Error ? err.message : String(err),
    };
  } finally {
    clearTimeout(timer);
  }
}

/** GET auf eine (Metadaten-)URL. */
export async function getUrl(url: string, timeoutMs: number, origin?: string): Promise<ProbeResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const headers: Record<string, string> = { accept: "application/json" };
    if (origin) headers["origin"] = origin;
    const res = await fetch(url, {
      method: "GET",
      headers,
      signal: controller.signal,
      redirect: "manual",
    });
    const text = await res.text();
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
    return {
      status: res.status,
      ok: res.ok,
      headers: headersToObject(res.headers),
      json,
      text: text.slice(0, 4000),
    };
  } catch (err) {
    return { status: 0, ok: false, headers: {}, error: err instanceof Error ? err.message : String(err) };
  } finally {
    clearTimeout(timer);
  }
}

/** Well-known-URL relativ zum Origin der Ziel-URL bilden. */
export function wellKnown(target: string, path: string): string | undefined {
  try {
    const u = new URL(target);
    return `${u.protocol}//${u.host}${path}`;
  } catch {
    return undefined;
  }
}
