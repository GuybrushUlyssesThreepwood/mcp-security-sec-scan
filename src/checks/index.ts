// Registrierte Checks in Ausführungsreihenfolge.
// 10 fokussierte Auth-/Tenancy-/Transport-Checks, soweit von außen prüfbar.

import type { Check } from "../types.js";
import { authRequired, oauthMetadataPkce, errorVerbosity } from "./auth.js";
import { tlsEnforced, corsConfig, originValidation, securityHeaders } from "./transport.js";
import { unauthTools, toolPoisoning } from "./tools.js";
import { rateLimiting } from "./ratelimit.js";

export const CHECKS: Check[] = [
  tlsEnforced,
  authRequired,
  securityHeaders, // nutzt shared.unauthInitialize aus authRequired
  unauthTools,
  oauthMetadataPkce,
  toolPoisoning,
  corsConfig,
  originValidation,
  errorVerbosity,
  rateLimiting,
];
