/**
 * @cuny-ai-lab/cail-identity — the CAIL identity-JWT verifier.
 *
 * A single pure async function that verifies the gateway-signed CAIL identity
 * JWT (HS256) and returns a normalized identity, or `null` on ANY failure.
 *
 * Design contract (see README + CAIL_IDENTITY_PRIMITIVE_SPEC.md):
 *   - Pure Web Crypto only (crypto.subtle, TextEncoder, atob). Runs unchanged
 *     in Cloudflare Workers and Node >=20.
 *   - Algorithm is PINNED to HS256 in code; the token never chooses it.
 *   - `secret` is a function argument — never stored, never logged.
 *   - Fail closed: any ambiguity returns `null`. Never throws, never reveals a
 *     failure reason (no oracle).
 *   - Identity comes ONLY from a validly-signed token — no header trust, no
 *     subject derivation.
 */
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
//# sourceMappingURL=index.d.ts.map