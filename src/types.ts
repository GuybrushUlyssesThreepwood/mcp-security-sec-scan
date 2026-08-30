// Core data types for mcp-sec-scan.

export type Severity = "pass" | "info" | "warn" | "problem" | "skipped";

export interface Finding {
  /** Check id, e.g. "auth-required". Stable, used for report references. */
  id: string;
  /** Menschliche Kurzbezeichnung. */
  title: string;
  severity: Severity;
  /** Was wurde beobachtet. */
  detail: string;
  /** Handlungsempfehlung (leer bei pass). */
  remediation?: string;
  /** Verweis auf Checklisten-Punkt / Doku. */
  reference?: string;
}

export interface ScanContext {
  /** Ziel-URL des MCP-Servers (Streamable HTTP Endpoint). */
  url: string;
  /** Optional bearer token for authenticated deep checks. */
  token?: string;
  /** Netzwerk-Timeout je Request (ms). */
  timeoutMs: number;
  /** true = non-destructive extra probes (e.g. the rate-limit burst) are allowed. */
  activeProbes: boolean;
  /**
   * true = observation mode. Only checks run that send no request to the
   * MCP-Endpunkt selbst senden: Auswertung der URL sowie GETs auf die standardisierten
   * `.well-known` discovery paths (RFC 8414 / RFC 9728), which are published precisely to be
   * unauthentifiziert abgerufen zu werden. Kein JSON-RPC, kein Handshake, keine Tool-Auflistung,
   * no provoked errors, no burst. For surveys across third-party servers without a mandate.
   */
  passive: boolean;
}

/** Ein Check bekommt den Kontext und liefert 1..n Findings. */
export interface Check {
  id: string;
  title: string;
  /**
   * true = the check sends no request to the MCP endpoint itself and therefore also runs in
   * Beobachtungsmodus (`--passive`). Erlaubt sind nur URL-Auswertung und GETs auf
   * `.well-known`-Discovery-Pfade. Fehlt das Flag, gilt der Check als nicht passiv.
   */
  passiveSafe?: boolean;
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
  /** RFC-9728 Protected-Resource-Metadaten (/.well-known/oauth-protected-resource), einmal geladen. */
  prm?: ProbeResult;
}

export interface ProbeResult {
  status: number;
  ok: boolean;
  headers: Record<string, string>;
  /** Geparster JSON-RPC-Body (falls vorhanden). */
  json?: unknown;
  /** Raw text (truncated) for heuristics. */
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
  /** "passive" = Beobachtungsmodus (nur URL + .well-known-GETs), "standard" = voller externer Scan. */
  mode: "passive" | "standard";
  findings: Finding[];
  summary: Record<Severity, number>;
}
