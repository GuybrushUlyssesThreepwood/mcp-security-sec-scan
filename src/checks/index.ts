// Registered checks, in execution order.
// 12 focused auth/tenancy/transport checks, as far as they are verifiable from the outside.

import type { Check } from "../types.js";
import { authRequired, oauthMetadataPkce, resourceMetadata, errorVerbosity } from "./auth.js";
import { tlsEnforced, corsConfig, originValidation, securityHeaders, sessionIdEntropy } from "./transport.js";
import { unauthTools, toolPoisoning } from "./tools.js";
import { rateLimiting } from "./ratelimit.js";

export const CHECKS: Check[] = [
  tlsEnforced,
  authRequired,
  securityHeaders, // uses shared.unauthInitialize from authRequired
  sessionIdEntropy, // uses shared.unauthInitialize from authRequired
  unauthTools,
  oauthMetadataPkce, // loads/caches shared.prm
  resourceMetadata, // uses shared.prm + WWW-Authenticate from authRequired
  toolPoisoning,
  corsConfig,
  originValidation,
  errorVerbosity,
  rateLimiting,
];
