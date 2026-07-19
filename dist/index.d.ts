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
/**
 * Stable pseudonymous app-principal identifier (ADR-0007).
 *
 * App principals are headless applications with their own spend partition.
 * The `app-` prefix is disjoint from the user `cail-` prefix by construction,
 * so an app subject can never collide with a user subject in a spend
 * partition, an audit row, or a workspace key.
 */
export declare const APP_SUBJECT_PATTERN: RegExp;
/** True only for the canonical stable CAIL app-principal subject. */
export declare function isAppSubject(value: unknown): value is string;
/**
 * Derive the stable pseudonymous CAIL app-principal subject (ADR-0007).
 *
 * `app-` + the first 32 hexadecimal characters of
 * HMAC-SHA256(subjectSalt, `app|${appId}`).
 *
 * The same HMAC construction as the user subject, namespaced by the literal
 * `app|` domain-separation prefix and the disjoint `app-` output prefix. The
 * app id is a stable control-plane identifier chosen by a trusted issuing
 * service (never user-controlled request data) and is used byte-exact — no
 * canonicalization, because there is no upstream-IdP quirk to absorb.
 */
export declare function deriveAppSubject(appId: string, subjectSalt: string): Promise<string>;
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
/** Why an identity verification CONFIG failed to load. Operator error, not a token error. */
export type IdentityConfigErrorReason = "jwks_missing" | "jwks_malformed" | "issuer_missing" | "issuer_unsupported";
export interface ParseIdentityConfigInput {
    /** Raw JWKS JSON string, e.g. the `CAIL_IDENTITY_JWKS` environment value. */
    jwks: string | undefined;
    /** Exact expected issuer, e.g. the `CAIL_IDENTITY_ISSUER` environment value. */
    issuer: string | undefined;
    /** Optional exact-match allowlist the configured issuer must belong to. */
    supportedIssuers?: readonly string[];
}
export type ParseIdentityConfigResult = {
    ok: true;
    jwks: JSONWebKeySet;
    issuer: string;
} | {
    ok: false;
    reason: IdentityConfigErrorReason;
};
/**
 * Parse and validate the identity VERIFICATION CONFIG (JWKS string + issuer).
 *
 * This is the canonical config-error-vs-invalid-token boundary: a token that
 * fails validation against a successfully loaded JWKS is a CLIENT error (401,
 * `verifyIdentityJwt` returns null), while a server that cannot load or parse
 * its own verification config is an OPERATOR error the caller must surface as
 * 5xx (503) with a structured log — otherwise a misconfiguration presents as
 * every user's auth silently failing. (Precedent: Envoy JWT filter #41669.)
 *
 * Config-invalid is a VALUE here, never an exception: the function does not
 * throw. Structural JWKS validation only — a well-formed JWK Set object with a
 * `keys` array of objects. An empty `keys` array is a loaded (if useless)
 * config; per-key selection remains `verifyIdentityJwt`'s token-validation
 * concern and still fails closed to null.
 */
export declare function parseIdentityConfig(input: ParseIdentityConfigInput): ParseIdentityConfigResult;
/**
 * Verify a CAIL RS256 identity JWT against an in-memory public JWKS.
 * Any malformed, unauthorized, unsupported, or ambiguous input returns null.
 */
export declare function verifyIdentityJwt(token: string, jwks: JSONWebKeySet, opts: VerifyIdentityJwtOptions): Promise<CailIdentity | null>;
//# sourceMappingURL=index.d.ts.map