#!/usr/bin/env node
// mcp-sec-scan CLI — externer Security-Scan für Remote-MCP-Server (Streamable HTTP).

import { writeFile } from "node:fs/promises";
import { runScan, SCANNER_VERSION } from "./scanner.js";
import { toTerminal, toMarkdown, toSarif, exitCode } from "./report.js";
import type { ScanContext } from "./types.js";

interface Args {
  url?: string;
  token?: string;
  markdown?: string;
  json?: string;
  sarif?: string;
  timeoutMs: number;
  active: boolean;
  passive: boolean;
  noColor: boolean;
  ci: boolean;
  help: boolean;
  version: boolean;
}

function parseArgs(argv: string[]): Args {
  const a: Args = { timeoutMs: 10000, active: false, passive: false, noColor: false, ci: false, help: false, version: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case "-h": case "--help": a.help = true; break;
      case "-v": case "--version": a.version = true; break;
      case "--token": a.token = argv[++i]; break;
      case "--markdown": case "-m": a.markdown = argv[++i]; break;
      case "--json": a.json = argv[++i]; break;
      case "--sarif": a.sarif = argv[++i]; break;
      case "--timeout": a.timeoutMs = Number(argv[++i]) || 10000; break;
      case "--active": a.active = true; break;
      case "--passive": a.passive = true; break;
      case "--no-color": a.noColor = true; break;
      case "--ci": a.ci = true; break;
      default:
        if (!arg.startsWith("-") && !a.url) a.url = arg;
    }
  }
  // Token auch aus Env (sicherer als CLI-Historie).
  if (!a.token && process.env.MCP_SEC_SCAN_TOKEN) a.token = process.env.MCP_SEC_SCAN_TOKEN;
  return a;
}

const HELP = `mcp-sec-scan v${SCANNER_VERSION}
Opinionated remote-MCP auth & tenancy security scanner.

USAGE
  mcp-sec-scan <url> [options]

OPTIONS
  --token <t>        Bearer token for authenticated deep checks (or env MCP_SEC_SCAN_TOKEN)
  -m, --markdown <f> Write a Markdown report to file <f>
  --json <f>         Write raw JSON report to file <f>
  --sarif <f>        Write a SARIF 2.1.0 report to file <f> (GitHub Code Scanning)
  --timeout <ms>     Per-request timeout in ms (default 10000)
  --active           Enable active probes (small rate-limit burst) — needs explicit permission
  --passive          Observation mode: no requests to the MCP endpoint itself.
                     Runs only URL inspection and GETs on the standardised .well-known
                     discovery paths (RFC 8414 / RFC 9728), which exist to be fetched
                     unauthenticated. No JSON-RPC, no handshake, no tool listing, no
                     provoked errors, no burst. Use for surveys across third-party
                     servers where you hold no per-server authorisation.
  --no-color         Disable colored terminal output
  --ci               CI mode: exit 2 on any PROBLEM, 1 on any WARN, else 0
  -h, --help         Show this help
  -v, --version      Show version

LEGAL
  The default mode is an EXTERNAL but NOT purely observational scan: it performs an
  unauthenticated MCP handshake, attempts to list tools and deliberately provokes an
  error response. Run it only against servers you own or are explicitly authorised to
  test, and keep that authorisation on record. Unsolicited scanning of third-party
  systems may be unlawful (in Germany e.g. §§ 202a ff., 303b StGB) and professional
  indemnity insurers typically cover assessment work only with the operator's mandate.
  --passive exists for exactly the case where you have no such mandate.

EXAMPLES
  mcp-sec-scan https://example.com/mcp --active -m report.md   # authorised full scan
  mcp-sec-scan https://example.com/mcp --passive --json out.json  # survey, no mandate
`;

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.version) { console.log(SCANNER_VERSION); return; }
  if (args.help || !args.url) { console.log(HELP); process.exitCode = args.url ? 0 : 1; return; }

  // --passive und --active widersprechen sich: der eine verbietet jede Anfrage an den Endpunkt,
  // der andere erzeugt bewusst Last darauf. Hart abbrechen statt still eines gewinnen zu lassen —
  // wer beides tippt, hat eine falsche Vorstellung davon, was gleich passiert.
  if (args.passive && args.active) {
    console.error("Fehler: --passive und --active schließen sich aus. --passive sendet keine Anfrage an den Endpunkt, --active erzeugt bewusst Last darauf.");
    process.exitCode = 1;
    return;
  }
  if (args.passive && args.token) {
    console.error("Fehler: --passive und --token schließen sich aus. Ein Token bedeutet, dass du autorisiert bist — dann ist der Beobachtungsmodus nicht nötig.");
    process.exitCode = 1;
    return;
  }

  const ctx: ScanContext = {
    url: args.url!,
    token: args.token,
    timeoutMs: args.timeoutMs,
    activeProbes: args.active,
    passive: args.passive,
  };

  const report = await runScan(ctx);

  process.stdout.write(toTerminal(report, !args.noColor));

  if (args.markdown) {
    await writeFile(args.markdown, toMarkdown(report), "utf8");
    console.log(`Markdown report written to ${args.markdown}`);
  }
  if (args.json) {
    await writeFile(args.json, JSON.stringify(report, null, 2), "utf8");
    console.log(`JSON report written to ${args.json}`);
  }
  if (args.sarif) {
    await writeFile(args.sarif, JSON.stringify(toSarif(report), null, 2), "utf8");
    console.log(`SARIF report written to ${args.sarif}`);
  }

  // process.exitCode statt process.exit(): Node beendet erst, wenn stdout geflusht und
  // offene Handles geschlossen sind. Ein hartes process.exit() kann auf Windows mit
  // Node 24 mit dem Teardown offener Sockets/Pipes kollidieren (libuv-Assertion) und den
  // Exit-Code verfälschen — genau der, auf den ein CI-Gate sich verlässt.
  if (args.ci) process.exitCode = exitCode(report);
}

main().catch((err) => {
  console.error("Fatal:", err instanceof Error ? err.message : err);
  process.exitCode = 3;
});
