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
  /** Verweis auf Checklisten-Punkt / Doku. */
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
  /**
   * true = Beobachtungsmodus. Es laufen ausschließlich Checks, die keine Anfrage an den
   * MCP-Endpunkt selbst senden: Auswertung der URL sowie GETs auf die standardisierten
   * `.well-known`-Discovery-Pfade (RFC 8414 / RFC 9728), die genau dafür veröffentlicht werden,
   * unauthentifiziert abgerufen zu werden. Kein JSON-RPC, kein Handshake, keine Tool-Auflistung,
   * keine provozierten Fehler, kein Burst. Für Erhebungen über fremde Server ohne Einzelauftrag.
   */
  passive: boolean;
}

/** Ein Check bekommt den Kontext und liefert 1..n Findings. */
export interface Check {
  id: string;
  title: string;
  /**
   * true = der Check sendet keine Anfrage an den MCP-Endpunkt selbst und läuft daher auch im
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
  /** "passive" = Beobachtungsmodus (nur URL + .well-known-GETs), "standard" = voller externer Scan. */
  mode: "passive" | "standard";
  findings: Finding[];
  summary: Record<Severity, number>;
}
