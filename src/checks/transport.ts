// Transport/CORS checks: TLS enforcement, CORS, origin validation, security headers, session-id entropy.

import type { Check, Finding, ScanContext, SharedState } from "../types.js";
import { getUrl, postRpc, jsonRpc, initializeParams } from "../probe.js";

const REF = "MCP Security Checklist #15";
const REF_SESSION = "MCP Security Checklist Session-Hijacking";

function safeProtocol(url: string): string {
  try {
    return new URL(url).protocol;
  } catch {
    return "";
  }
}

export const tlsEnforced: Check = {
  passiveSafe: true,
  id: "tls-enforced",
  title: "TLS enforced (no cleartext HTTP)",
  async run(ctx: ScanContext): Promise<Finding[]> {
    let proto = "";
    try {
      proto = new URL(ctx.url).protocol;
    } catch {
      return [{ id: this.id, title: this.title, severity: "info", detail: "URL could not be parsed.", reference: REF }];
    }
    if (proto === "https:") {
      return [{
        id: this.id, title: this.title, severity: "pass",
        detail: "The endpoint is addressed over HTTPS.",
        reference: REF,
      }];
    }
    return [{
      id: this.id, title: this.title, severity: "problem",
      detail: `The endpoint uses '${proto}' instead of HTTPS. Tokens and data would travel in cleartext.`,
      remediation: "Serve remote MCP over HTTPS only; redirect HTTP to HTTPS or refuse it.",
      reference: REF,
    }];
  },
};

export const corsConfig: Check = {
  id: "cors-config",
  title: "CORS configuration",
  async run(ctx: ScanContext): Promise<Finding[]> {
    // Request with a foreign origin and check for reflection/wildcard.
    const evilOrigin = "https://mcp-sec-scan.example.attacker";
    const probe = await getUrl(ctx.url, ctx.timeoutMs, evilOrigin);
    const acao = probe.headers["access-control-allow-origin"];
    const acac = probe.headers["access-control-allow-credentials"];

    if (!acao) {
      return [{
        id: this.id, title: this.title, severity: "pass",
        detail: "No Access-Control-Allow-Origin set for a foreign origin (browsers block cross-origin access).",
        reference: REF,
      }];
    }
    if (acao === "*" && acac === "true") {
      return [{
        id: this.id, title: this.title, severity: "problem",
        detail: "ACAO '*' together with Allow-Credentials 'true' — an unsafe combination (credentials for every origin).",
        remediation: "No wildcard with credentials. Use an origin allow-list.",
        reference: REF,
      }];
    }
    if (acao === evilOrigin) {
      return [{
        id: this.id, title: this.title, severity: "warn",
        detail: `The server reflects an arbitrary origin (${evilOrigin}) in ACAO — effectively open CORS.`,
        remediation: "Check the origin against a fixed allow-list instead of reflecting it.",
        reference: REF,
      }];
    }
    if (acao === "*") {
      return [{
        id: this.id, title: this.title, severity: "warn",
        detail: "ACAO '*' (open CORS without credentials). Usually fine for purely token-based access, but set it deliberately.",
        reference: REF,
      }];
    }
    return [{
      id: this.id, title: this.title, severity: "info",
      detail: `ACAO set to '${acao}'.`,
      reference: REF,
    }];
  },
};

export const originValidation: Check = {
  id: "origin-validation",
  title: "Origin header validation (DNS rebinding)",
  async run(ctx: ScanContext): Promise<Finding[]> {
    // MCP Streamable HTTP: servers MUST validate the Origin header to prevent DNS rebinding.
    // We send 'initialize' with a foreign origin and check whether it is refused.
    const evilOrigin = "https://dns-rebind.attacker.example";
    const probe = await postRpc(ctx.url, jsonRpc("initialize", initializeParams()), {
      timeoutMs: ctx.timeoutMs,
      token: ctx.token,
      extraHeaders: { origin: evilOrigin },
    });

    if (probe.error) {
      return [{
        id: this.id, title: this.title, severity: "info",
        detail: `No result (network/timeout): ${probe.error}`,
        reference: REF,
      }];
    }
    if (probe.status === 400 || probe.status === 403) {
      return [{
        id: this.id, title: this.title, severity: "pass",
        detail: `Request with a foreign origin (${evilOrigin}) refused (HTTP ${probe.status}).`,
        reference: REF,
      }];
    }
    if (probe.status === 401) {
      return [{
        id: this.id, title: this.title, severity: "info",
        detail: `Auth is enforced before the origin check (HTTP 401) — origin validation cannot be verified unambiguously from the outside.`,
        remediation: "Make sure the origin is checked against an allow-list server-side (for authenticated requests too).",
        reference: REF,
      }];
    }
    if (probe.status >= 200 && probe.status < 300) {
      return [{
        id: this.id, title: this.title, severity: "warn",
        detail: `The server accepts 'initialize' with a foreign origin (${evilOrigin}, HTTP ${probe.status}) without refusing it. The MCP Streamable HTTP specification requires origin validation against DNS rebinding — especially critical for servers reachable locally or on an internal network.`,
        remediation: "Check the Origin header against a fixed allow-list and refuse foreign origins with 403; bind the server only to the interfaces it needs.",
        reference: REF,
      }];
    }
    return [{
      id: this.id, title: this.title, severity: "info",
      detail: `Unexpected status on 'initialize' with a foreign origin: HTTP ${probe.status}.`,
      reference: REF,
    }];
  },
};

export const securityHeaders: Check = {
  id: "security-headers",
  title: "Security headers (HSTS, nosniff)",
  async run(ctx: ScanContext, shared: SharedState): Promise<Finding[]> {
    // Reuse what 'auth-required' already determined; otherwise probe once here.
    // Without a token: the result lands in shared.unauthInitialize, and 'resource-metadata' infers
    // from it whether the server enforces auth. A token here would distort that inference.
    let headers = shared.unauthInitialize?.headers;
    if (!headers) {
      const probe = await postRpc(ctx.url, jsonRpc("initialize", initializeParams()), {
        timeoutMs: ctx.timeoutMs,
      });
      shared.unauthInitialize = probe;
      headers = probe.headers;
    }
    if (!headers || Object.keys(headers).length === 0) {
      return [{
        id: this.id, title: this.title, severity: "info",
        detail: "No response headers could be determined (server unreachable?).",
        reference: REF,
      }];
    }

    const isHttps = safeProtocol(ctx.url) === "https:";
    const missing: string[] = [];
    if (isHttps && !headers["strict-transport-security"]) missing.push("Strict-Transport-Security (HSTS)");
    if (!headers["x-content-type-options"]) missing.push("X-Content-Type-Options: nosniff");

    if (missing.length === 0) {
      return [{
        id: this.id, title: this.title, severity: "pass",
        detail: `Security headers present${isHttps ? " (including HSTS)" : ""}.`,
        reference: REF,
      }];
    }
    return [{
      id: this.id, title: this.title, severity: "warn",
      detail: `Missing security headers: ${missing.join(", ")}.`,
      remediation: "Over HTTPS, set 'Strict-Transport-Security: max-age=15552000; includeSubDomains' and send 'X-Content-Type-Options: nosniff'.",
      reference: REF,
    }];
  },
};

/** Shannon entropy per character (bits). A rough measure of how random a session id is. */
function shannonBitsPerChar(s: string): number {
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of freq.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Returns a reason when the session id looks weak, otherwise null. Deliberately conservative. */
function assessSessionId(sid: string): string | null {
  if (sid.length < 16) return `too short (${sid.length} characters, < 16)`;
  if (/^[0-9]+$/.test(sid)) return "digits only (easily guessed/sequential)";
  if (/session|sess-|test|demo|token|admin|default|guest/i.test(sid)) return "contains a predictable plaintext word";
  const distinct = new Set(sid).size;
  if (distinct < 8) return `low character variety (only ${distinct} distinct characters)`;
  const bits = shannonBitsPerChar(sid);
  if (bits < 2.5) return `low entropy (${bits.toFixed(1)} bits/character)`;
  return null;
}

/** Never echo the session id in full (on a real target it may be an active token). */
function redactSid(sid: string): string {
  return `${sid.slice(0, 4)}…, ${sid.length} characters`;
}

export const sessionIdEntropy: Check = {
  id: "session-id-entropy",
  title: "Session-id unpredictability (mcp-session-id)",
  async run(ctx: ScanContext, shared: SharedState): Promise<Finding[]> {
    // MCP Streamable HTTP: session ids MUST be cryptographically secure (otherwise session hijacking).
    // Prefer the initialize response already seen; probe once here only if there is none.
    let headers = shared.unauthInitialize?.headers;
    if (!shared.unauthInitialize) {
      // Without a token — see the reasoning in the 'security-headers' check.
      const probe = await postRpc(ctx.url, jsonRpc("initialize", initializeParams()), {
        timeoutMs: ctx.timeoutMs,
      });
      shared.unauthInitialize = probe;
      headers = probe.headers;
    }

    const sid = headers?.["mcp-session-id"];
    if (!sid) {
      return [{
        id: this.id, title: this.title, severity: "info",
        detail: "The server issues no 'mcp-session-id' response header (likely stateless) — no session vector guessable from the header.",
        reference: REF_SESSION,
      }];
    }

    const weak = assessSessionId(sid);
    if (weak) {
      return [{
        id: this.id, title: this.title, severity: "warn",
        detail: `The issued 'mcp-session-id' (${redactSid(sid)}) looks weak: ${weak}. Guessable or brute-forceable -> risk of session hijacking.`,
        remediation: "Use cryptographically secure session ids (CSPRNG, >=128 bits of entropy, e.g. crypto.randomUUID); do not derive them sequentially or from plaintext.",
        reference: REF_SESSION,
      }];
    }
    return [{
      id: this.id, title: this.title, severity: "pass",
      detail: `The issued 'mcp-session-id' has sufficient length and entropy (${sid.length} characters, high character variety).`,
      reference: REF_SESSION,
    }];
  },
};
