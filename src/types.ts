// Kern-Datentypen für mcp-sec-scan.

export type Severity = "pass" | "info" | "warn" | "problem" | "skipped";

export interface Finding {
  /** Check-ID, z. B. "auth-required". Stabil, für Report-Referenzen. */
  id: string;
  /** Menschliche Kurzbezeichnung. */
  title: string;
  severity: Severity;
  /** Was wurde beobachtet. */
  detail: string;
  /** Handlungsempfehlung (leer bei pass). */
  remediation?: string;
  /** Verweis auf Checklisten-Punkt (T-003) / Doku. */
  reference?: string;
}

export interface ScanContext {
  /** Ziel-URL des MCP-Servers (Streamable HTTP Endpoint). */
  url: string;
  /** Optionales Bearer-Token für authentifizierte Tiefenchecks. */
  token?: string;
  /** Netzwerk-Timeout je Request (ms). */
  timeoutMs: number;
  /** true = zerstörungsfreie Extra-Probes (z. B. Rate-Limit-Burst) erlaubt. */
  activeProbes: boolean;
}

/** Ein Check bekommt den Kontext und liefert 1..n Findings. */
export interface Check {
  id: string;
  title: string;
  run(ctx: ScanContext, shared: SharedState): Promise<Finding[]>;
}

/** Zwischen Checks geteilte Beobachtungen (einmal ermittelt, mehrfach genutzt). */
export interface SharedState {
  /** Ergebnis eines unauthentifizierten initialize-Versuchs. */
  unauthInitialize?: ProbeResult;
  /** Tool-Liste, falls erreichbar (unauth oder via Token). */
  tools?: McpTool[];
  /** Protokoll-Version aus initialize, falls erreichbar. */
  protocolVersion?: string;
}

export interface ProbeResult {
  status: number;
  ok: boolean;
  headers: Record<string, string>;
  /** Geparster JSON-RPC-Body (falls vorhanden). */
  json?: unknown;
  /** Roher Text (gekürzt) für Heuristiken. */
  text?: string;
  error?: string;
}

export interface McpTool {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

export interface ScanReport {
  target: string;
  scannedAt: string;
  scannerVersion: string;
  findings: Finding[];
  summary: Record<Severity, number>;
}
