---
name: New check proposal
about: Propose a new auth/tenancy/transport check
title: "[check] "
labels: enhancement
---

**Check name**
Short id (e.g. `dns-rebinding`).

**What it observes**
What can be detected from the outside. State how many requests it costs and whether any of them reach the MCP endpoint itself.

**Why it matters**
The risk / attack scenario.

**Detection method**
How to determine pass/warn/problem. Note if it requires `--active` or a token.

**Reference**
Spec section / OWASP / documented incident (with date).
