// Single source of truth for the scanner version.
// Wird von scanner.ts (Report), probe.ts (clientInfo) und cli.ts (Re-Export) genutzt,
// damit die Version nicht an mehreren Stellen driftet. package.json manuell synchron halten.

export const SCANNER_VERSION = "1.3.1";
