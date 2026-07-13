/**
 * @cuny-ai-lab/cail-identity — the CAIL identity-JWT verifier.
 *
 * Pure async verifiers for gateway-signed CAIL identity JWTs. V1 accepts HS256
 * with a shared secret; V2 accepts RS256 with an in-memory public JWKS. Both
 * return a normalized identity, or `null` on ANY failure.
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
export interface VerifyOptions {
    /** Unix seconds "now". Default: Math.floor(Date.now() / 1000). */
    now?: number;
    /**
     * Symmetric clock leeway in seconds applied to `exp` and `nbf`.
     * Default 60 (RFC 7519 leeway across independently-NTP'd hosts).
     * 0 = strict RFC boundary (`exp <= now` rejects, `nbf > now` rejects).
     */
    clockToleranceSeconds?: number;
    /**
     * EXACT-match issuer allowlist (I8). A token is accepted only when its `iss`
     * claim is an exact member of this array — NOT a suffix or substring match.
     * Absent or empty → reject ALL tokens (fail closed, loud): the caller must
     * opt into every issuer it trusts. Compose from `CAIL_CANONICAL_ISSUER` /
     * `CAIL_STAGING_ISSUER` or supply your own.
     */
    allowedIssuers?: string[];
}
/** Canonical production issuer — list it in `allowedIssuers` to accept prod. */
export declare const CAIL_CANONICAL_ISSUER = "https://tools.ailab.gc.cuny.edu/cail-sso";
/** Staging issuer — list it in `allowedIssuers` to accept staging. */
export declare const CAIL_STAGING_ISSUER = "https://tools.cuny.qzz.io/cail-sso";
export declare function verifyIdentityJwt(token: string, secret: string, opts?: VerifyOptions): Promise<CailIdentity | null>;
export interface VerifyIdentityJwtV2Options {
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
export declare function verifyIdentityJwtV2(token: string, jwks: JSONWebKeySet, opts: VerifyIdentityJwtV2Options): Promise<CailIdentity | null>;
//# sourceMappingURL=index.d.ts.map