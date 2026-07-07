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
  noColor: boolean;
  ci: boolean;
  help: boolean;
  version: boolean;
}

function parseArgs(argv: string[]): Args {
  const a: Args = { timeoutMs: 10000, active: false, noColor: false, ci: false, help: false, version: false };
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
  --active           Enable active probes (small rate-limit burst)
  --no-color         Disable colored terminal output
  --ci               CI mode: exit 2 on any PROBLEM, 1 on any WARN, else 0
  -h, --help         Show this help
  -v, --version      Show version

LEGAL
  Scan only servers you own or are explicitly authorized to test.
  Unsolicited scanning of third-party systems may be unlawful.

EXAMPLE
  mcp-sec-scan https://example.com/mcp --active -m report.md
`;

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.version) { console.log(SCANNER_VERSION); return; }
  if (args.help || !args.url) { console.log(HELP); process.exit(args.url ? 0 : 1); }

  const ctx: ScanContext = {
    url: args.url!,
    token: args.token,
    timeoutMs: args.timeoutMs,
    activeProbes: args.active,
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

  if (args.ci) process.exit(exitCode(report));
}

main().catch((err) => {
  console.error("Fatal:", err instanceof Error ? err.message : err);
  process.exit(3);
});
