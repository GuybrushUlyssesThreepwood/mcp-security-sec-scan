# Contributing to mcp-sec-scan

Thanks for your interest! This is a focused tool — **opinionated auth & tenancy checks for remote MCP
servers**. Contributions that keep that focus are very welcome.

## Development
```bash
npm install
npm run typecheck
npm test          # unit tests
npm run build
```

Integration self-test (scanner vs. the bundled vulnerable server):
```bash
node test/vulnerable-server.mjs &
node dist/cli.js http://127.0.0.1:8971/ --active --ci    # exits non-zero when findings are present
```

## Adding a check
1. Create `src/checks/<name>.ts` exporting a `Check` (see `src/types.ts`).
2. Register it in `src/checks/index.ts`.
3. Add a unit test in `test/unit.test.ts` (keep it network-free where possible).
4. Update the README check list and `CHANGELOG.md`.

Checks should be **non-invasive by default**. Anything that sends more than a couple of requests belongs
behind the `--active` flag.

## Style
- TypeScript strict mode; no `any` in new code where avoidable.
- Findings must include a clear `detail` and, for non-`pass` results, a `remediation`.

## Pull requests
Small, focused PRs. Describe what the check observes and why it matters. All PRs run `typecheck`, `test`,
`build` and the self-test in CI.
