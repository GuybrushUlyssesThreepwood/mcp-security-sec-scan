// Registrierte Checks in Ausführungsreihenfolge.
// v1.0 bewusst schlank: 8 fokussierte Auth-/Tenancy-/Transport-Checks, soweit von außen prüfbar.

import type { Check } from "../types.js";
import { authRequired, oauthMetadataPkce, errorVerbosity } from "./auth.js";
import { tlsEnforced, corsConfig } from "./transport.js";
import { unauthTools, toolPoisoning } from "./tools.js";
import { rateLimiting } from "./ratelimit.js";

export const CHECKS: Check[] = [
  tlsEnforced,
  authRequired,
  unauthTools,
  oauthMetadataPkce,
  toolPoisoning,
  corsConfig,
  errorVerbosity,
  rateLimiting,
];
