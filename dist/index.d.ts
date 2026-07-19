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
 * OIDC Core defines `sub` as a case-sensitive opaque string; a compliant RP
 * compares it byte-for-byte and never normalizes. CAIL normalizes for ONE
 * documented reason: CUNYLogin is non-compliant and emits the same person as
 * two forms (`BOB` and `bob@login.cuny.edu`). So we normalize exactly and only
 * that quirk — ASCII whitespace trim, ASCII-only uppercase, one trailing
 * `@LOGIN.CUNY.EDU` realm removed — and leave everything else opaque.
 *
 * ASCII-only is load-bearing: it must produce byte-identical output to the
 * gate's LuaJIT `canonicalize_sub` (byte-wise `:upper()` and `%s`). A
 * Unicode-aware `toUpperCase()`/`trim()` would (a) diverge from the gate on
 * non-ASCII input and (b) *collide distinct people* — `ß`→`SS`, dotless `ı`→`I`,
 * NBSP trimming — a merge far beyond the realm quirk. CUNY subjects are ASCII,
 * so no real subject changes. It does not authenticate the value.
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