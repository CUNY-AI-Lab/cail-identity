/**
 * @cuny-ai-lab/cail-identity — the CAIL identity-JWT verifier.
 *
 * Pure async verification for gateway-signed RS256 CAIL identity JWTs using an
 * in-memory public JWKS. Returns a normalized identity, or `null` on ANY
 * failure.
 *
 * Design contract (see README):
 *   - JOSE/JWT protocol machinery is delegated to `jose`, which uses the same
 *     Web Crypto APIs across Cloudflare Workers, browsers, Bun, and Node >=20.
 *   - Each algorithm is PINNED in code; the token never chooses it.
 *   - Verification key material is passed in — never stored, never logged.
 *   - Fail closed: any ambiguity returns `null`. Never throws, never reveals a
 *     failure reason (no oracle).
 *   - Identity comes ONLY from a validly-signed token — no header trust, no
 *     subject derivation.
 */
import { type JSONWebKeySet } from "jose";
export interface CailIdentity {
    subject: string;
    email?: string;
    name?: string;
    entitlements: string[];
}
/** Canonical production issuer — list it in `allowedIssuers` to accept prod. */
export declare const CAIL_CANONICAL_ISSUER = "https://tools.ailab.gc.cuny.edu/cail-sso";
/** Staging issuer — list it in `allowedIssuers` to accept staging. */
export declare const CAIL_STAGING_ISSUER = "https://tools.cuny.qzz.io/cail-sso";
export interface VerifyIdentityJwtOptions {
    /** Required audience value. The token audience may be a scalar or array. */
    expectedAudience: string;
    /** Required exact-match issuer allowlist. */
    allowedIssuers: string[];
    /** Unix seconds "now". Default: Math.floor(Date.now() / 1000). */
    now?: number;
    /** Symmetric clock leeway in seconds. Default 60. */
    clockToleranceSeconds?: number;
}
/**
 * Verify a CAIL RS256 identity JWT against an in-memory public JWKS.
 * Any malformed, unauthorized, unsupported, or ambiguous input returns null.
 */
export declare function verifyIdentityJwt(token: string, jwks: JSONWebKeySet, opts: VerifyIdentityJwtOptions): Promise<CailIdentity | null>;
//# sourceMappingURL=index.d.ts.map