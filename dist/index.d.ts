/**
 * @cuny-ai-lab/cail-identity — the CAIL identity-JWT verifier.
 *
 * Pure Web Crypto helpers for the stable CAIL subject and gateway-signed
 * RS256 CAIL identity JWTs.
 *
 * Design contract (see README):
 *   - JOSE/JWT protocol machinery is delegated to `jose`, which uses the same
 *     Web Crypto APIs across Cloudflare Workers, browsers, Bun, and Node >=20.
 *   - Each algorithm is PINNED in code; the token never chooses it.
 *   - Verification key material is passed in — never stored, never logged.
 *   - Fail closed: any ambiguity returns `null`. Never throws, never reveals a
 *     failure reason (no oracle).
 *   - A verified token must contain the stable pseudonymous CAIL subject.
 *   - Subject derivation is explicit and intended only for a trusted CUNY
 *     authentication boundary, never for user-controlled request data.
 */
import { type JSONWebKeySet } from "jose";
export interface CailIdentity {
    subject: string;
    email?: string;
    name?: string;
    entitlements: string[];
}
/** Stable pseudonymous identifier shared across CAIL applications. */
export declare const CAIL_SUBJECT_PATTERN: RegExp;
/** True only for the canonical stable CAIL subject representation. */
export declare function isCailSubject(value: unknown): value is string;
/**
 * Canonicalize the trusted CUNY OIDC subject used as pseudonym input.
 *
 * This preserves the established CAIL contract: trim, uppercase, and remove
 * one trailing `@LOGIN.CUNY.EDU` realm. It does not authenticate the value.
 */
export declare function canonicalizeCunySubject(subject: string): string;
export interface DeriveCailSubjectOptions {
    /** Exact trusted OIDC issuer; it namespaces otherwise identical subjects. */
    issuer: string;
    /** Subject returned by the trusted CUNY OIDC provider. */
    oidcSubject: string;
    /** Secret stable salt, supplied only at the identity/authentication boundary. */
    subjectSalt: string;
}
/**
 * Derive the established stable pseudonymous CAIL subject.
 *
 * `cail-` + the first 32 hexadecimal characters of
 * HMAC-SHA256(subjectSalt, `${issuer}|${canonicalSubject}`).
 */
export declare function deriveCailSubject(options: DeriveCailSubjectOptions): Promise<string>;
/** Canonical production issuer — list it in `allowedIssuers` to accept prod. */
export declare const CAIL_CANONICAL_ISSUER = "https://tools.ailab.gc.cuny.edu/cail-sso";
/** Staging issuer — list it in `allowedIssuers` to accept staging. */
export declare const CAIL_STAGING_ISSUER = "https://tools.cuny.qzz.io/cail-sso";
export interface VerifyIdentityJwtOptions {
    /** Required scalar audience value. */
    expectedAudience: string;
    /** Required exact-match issuer list containing exactly one value. */
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