// Registrierte Checks in Ausführungsreihenfolge.
// 12 fokussierte Auth-/Tenancy-/Transport-Checks, soweit von außen prüfbar.

import type { Check } from "../types.js";
import { authRequired, oauthMetadataPkce, resourceMetadata, errorVerbosity } from "./auth.js";
import { tlsEnforced, corsConfig, originValidation, securityHeaders, sessionIdEntropy } from "./transport.js";
import { unauthTools, toolPoisoning } from "./tools.js";
import { rateLimiting } from "./ratelimit.js";

export const CHECKS: Check[] = [
  tlsEnforced,
  authRequired,
  securityHeaders, // nutzt shared.unauthInitialize aus authRequired
  sessionIdEntropy, // nutzt shared.unauthInitialize aus authRequired
  unauthTools,
  oauthMetadataPkce, // lädt/cached shared.prm
  resourceMetadata, // nutzt shared.prm + WWW-Authenticate aus authRequired
  toolPoisoning,
  corsConfig,
  originValidation,
  errorVerbosity,
  rateLimiting,
];
