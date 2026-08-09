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
 *   - Invalid tokens fail closed to `null` without revealing a failure reason.
 *     Configuration is loaded separately and remains an owned operator error.
 *   - A verified token must contain the stable pseudonymous CAIL subject.
 *   - Exact `cail:gateway` tokens must carry the closed model-scope and
 *     namespaced budget-scope access claims; app-audience tokens ignore them.
 *   - Subject derivation is explicit and intended only for a trusted CUNY
 *     authentication boundary, never for user-controlled request data.
 */
export interface CailIdentity {
    subject: string;
    /** Separately keyed pseudonym for privacy-bounded operational events. */
    operationalSubject?: string;
    email?: string;
    name?: string;
    entitlements: string[];
    /** Signed Gateway model-access scopes; present only for `cail:gateway`. */
    scopes?: CailModelScope[];
    /** Signed Gateway accounting budget scope; present only for `cail:gateway`. */
    budgetScope?: CailBudgetScope;
}
/** Model-access scopes the Gateway identity contract recognizes. */
export type CailModelScope = "models:read" | "models:invoke" | "quota:read";
/** Budget scopes allowed on a person-bound Gateway identity. */
export type CailBudgetScope = "person" | "classroom" | "person-plus" | "admin";
/** Frozen vocabulary of model-access scopes accepted by Gateway tokens. */
export declare const CAIL_MODEL_SCOPES: readonly ["models:read", "models:invoke", "quota:read"];
/** Frozen vocabulary of budget scopes accepted by Gateway tokens. */
export declare const CAIL_BUDGET_SCOPES: readonly ["person", "classroom", "person-plus", "admin"];
/** Collision-resistant private claim carrying the Gateway budget partition. */
export declare const CAIL_BUDGET_SCOPE_CLAIM = "https://ailab.gc.cuny.edu/claims/budget_scope";
/** True only for the canonical stable CAIL subject representation. */
export declare function isCailSubject(value: unknown): value is string;
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
 * `cail-` + the first 32 hexadecimal characters of HMAC-SHA256 over the
 * versioned, UTF-8 byte-length-prefixed ownership-subject material.
 */
export declare function deriveCailSubject(options: DeriveCailSubjectOptions): Promise<string>;
/** True only for the canonical stable CAIL app-principal subject. */
export declare function isAppSubject(value: unknown): value is string;
/**
 * True for a canonical user or application principal subject.
 *
 * This helper validates identifiers only. It does not authenticate a caller;
 * services still obtain user subjects from a verified identity JWT and app
 * subjects from their trusted control plane.
 */
export declare function isCailPrincipalSubject(value: unknown): value is string;
export declare function isCailOperationalSubject(value: unknown): value is string;
export interface DeriveCailOperationalSubjectOptions {
    issuer: string;
    oidcSubject: string;
    /** A dedicated secret; do not reuse the ownership-subject salt. */
    operationalSubjectSalt: string;
}
/**
 * Derive the separately keyed pseudonym carried as the identity JWT `log_sub`
 * claim and used only for operational events.
 */
export declare function deriveCailOperationalSubject(options: DeriveCailOperationalSubjectOptions): Promise<string>;
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
/** Canonical production issuer — include it in `supportedIssuers` to accept prod. */
export declare const CAIL_CANONICAL_ISSUER = "https://tools.ailab.gc.cuny.edu/cail-sso";
/** Staging issuer — include it in `supportedIssuers` to accept staging. */
export declare const CAIL_STAGING_ISSUER = "https://tools.cuny.qzz.io/cail-sso";
declare const identityVerifierConfigBrand: unique symbol;
/**
 * Immutable verifier configuration produced only by
 * {@link loadIdentityVerifierConfig}.
 */
export interface IdentityVerifierConfig {
    readonly expectedAudience: string;
    readonly issuer: string;
    readonly clockToleranceSeconds: number;
    readonly keyIds: readonly string[];
    readonly [identityVerifierConfigBrand]: true;
}
/** Why identity verification CONFIG failed to load. Operator error, not a token error. */
export type IdentityVerifierConfigErrorReason = "jwks_missing" | "jwks_malformed" | "issuer_missing" | "issuer_unsupported" | "audience_missing" | "audience_malformed" | "timing_invalid";
export interface LoadIdentityVerifierConfigInput {
    /** Raw JWKS JSON string, e.g. the `CAIL_IDENTITY_JWKS` environment value. */
    jwks: string | undefined;
    /** Exact expected issuer, e.g. the `CAIL_IDENTITY_ISSUER` environment value. */
    issuer: string | undefined;
    /** Required scalar `aud` value for this service. */
    expectedAudience: string | undefined;
    /**
     * Optional exact-match authority for acceptable configured issuers.
     * Defaults to CAIL's canonical production and staging issuers.
     */
    supportedIssuers?: readonly string[];
    /** Test-only fixed Unix time. Production callers should omit this. */
    now?: number;
    /** Symmetric clock leeway in seconds. Default 60; maximum 300. */
    clockToleranceSeconds?: number;
}
export type LoadIdentityVerifierConfigResult = {
    ok: true;
    config: IdentityVerifierConfig;
} | {
    ok: false;
    reason: IdentityVerifierConfigErrorReason;
};
/**
 * Load, validate, import, and snapshot the complete verifier configuration.
 *
 * Every caller-supplied option is read at most once. JWKS data must arrive as
 * JSON, so imported keys have own-data properties rather than live
 * accessors/proxies. A failed load is an owned service-configuration error;
 * callers map it to service unavailable. Only a successfully loaded snapshot
 * may be passed to {@link verifyIdentityJwt}.
 */
export declare function loadIdentityVerifierConfig(input: LoadIdentityVerifierConfigInput): Promise<LoadIdentityVerifierConfigResult>;
/**
 * Verify a CAIL RS256 identity JWT using an immutable validated snapshot.
 *
 * Invalid tokens return `null`. Passing anything other than a snapshot from
 * {@link loadIdentityVerifierConfig} is a programmer/configuration error and
 * throws, so it cannot be mislabeled as invalid credentials.
 */
export declare function verifyIdentityJwt(token: string, config: IdentityVerifierConfig): Promise<CailIdentity | null>;
/** The audience every gateway keyring leg must carry. */
export declare const CAIL_GATEWAY_AUDIENCE = "cail:gateway";
/**
 * A signed-in person's audience-bound tokens as delivered by the issuing
 * doorway. Transport shape only — nothing here is verified. The application
 * MUST verify `appJwt` against its own audience before trusting anything,
 * and MUST pass `gatewayJwt` through {@link verifyKeyringGatewayJwt} before
 * storing or forwarding it. Claims inside `gatewayJwt` are never authority
 * for the application.
 */
interface IdentityKeyring {
    appJwt: string;
    gatewayJwt?: string;
}
/**
 * Read a keyring from request headers. Structural transport parsing only —
 * no signature, audience, expiry, or subject checks happen here.
 *
 * Fail-closed rule: a header that is present but not a single well-shaped
 * compact JWS invalidates the whole keyring (`null`), rather than salvaging
 * the other leg. Duplicate headers join with a comma and therefore fail the
 * shape check by construction. An absent identity header yields `null`; an
 * absent gateway header yields a keyring without that leg.
 */
export declare function readIdentityKeyring(headers: Headers): IdentityKeyring | null;
/**
 * Verify a keyring's gateway leg before the application stores or forwards
 * it: full {@link verifyIdentityJwt} verification against a gateway-audience
 * config, plus the keyring invariant that its subject equals the already
 * verified app-leg subject. Returns the gateway leg's identity, or `null`
 * when the leg is absent, invalid, or belongs to a different person.
 *
 * `config` must come from {@link loadIdentityVerifierConfig} with
 * `expectedAudience: "cail:gateway"`; anything else is a programmer error
 * and throws, so a misconfigured verifier cannot pass as invalid tokens.
 */
export declare function verifyKeyringGatewayJwt(keyring: IdentityKeyring, config: IdentityVerifierConfig, expectedSubject: string): Promise<CailIdentity | null>;
export {};
//# sourceMappingURL=index.d.ts.map