/**
 * @cuny-ai-lab/cail-identity/testing — blessed test fixtures.
 *
 * Import path: `@cuny-ai-lab/cail-identity/testing`. TEST SUPPORT ONLY — this
 * subpath never changes runtime verification/derivation behavior and the
 * runtime entry (`.`) never imports it, so bundles that don't import it pay
 * nothing for it.
 *
 * Why this exists: consumers kept inventing structurally invalid subjects
 * (`cail-abc123`, `user:${email}`) in their test fixtures, which broke on the
 * v4 canonical-subject adoption (`CAIL_SUBJECT_PATTERN` enforcement). These
 * helpers make the VALID shapes cheaper to reach than the invalid ones:
 *
 *   - {@link canonicalTestSubject} — deterministic, structurally canonical
 *     subject from a readable seed. No hand-maintained hex literals.
 *   - {@link TEST_SUBJECTS} — ready-made distinct canonical subjects.
 *   - {@link createTestIdentityIssuer} — an in-memory RS256 issuer whose
 *     minted identity JWTs verify against its own JWKS via
 *     `verifyIdentityJwt`, for tests that exercise the real verification
 *     boundary.
 *
 * No test-framework imports; pure Web-standard code plus `jose` (already a
 * runtime dependency of this package).
 */
import { type JSONWebKeySet } from "jose";
/**
 * Deterministic, structurally canonical CAIL test subject from a readable
 * seed: `cail-` + the first 32 lowercase hex characters of SHA-256(seed).
 *
 * Always matches `CAIL_SUBJECT_PATTERN` / `isCailSubject` — the same SHAPE
 * `deriveCailSubject` produces — so fixtures survive canonical-subject
 * enforcement. Distinct seeds give distinct subjects; the same seed always
 * gives the same subject, so fixtures stay tellable-apart without
 * hand-maintaining hex literals.
 *
 * NOT a pseudonymization function: it is unsalted, unkeyed plain SHA-256 and
 * must never be used outside tests. Production derivation is
 * `deriveCailSubject`.
 */
export declare function canonicalTestSubject(seed: string): string;
/**
 * Ready-made canonical test subjects for the common case. All distinct, all
 * matching `CAIL_SUBJECT_PATTERN`, each equal to
 * `canonicalTestSubject(<name>)`.
 */
export declare const TEST_SUBJECTS: {
    readonly alice: string;
    readonly bob: string;
    readonly carol: string;
};
export interface MintTestIdentityJwtOptions {
    /** `aud` claim — a string is the well-formed shape verifiers accept; a
     * string ARRAY (even one-element) mints the array-`aud` shape CAIL
     * verifiers must reject, signed by the same key the JWKS advertises. */
    audience: string | string[];
    /** `sub` claim. Default: {@link TEST_SUBJECTS}.alice. Any string is allowed
     * so fail-closed paths (non-canonical subjects) can be exercised too. */
    subject?: string;
    /** Optional `email` claim. */
    email?: string;
    /** Optional `name` claim. */
    name?: string;
    /** Optional `entitlements` claim. */
    entitlements?: string[];
    /** `iss` claim override. Default: the issuer the kit was created with. */
    issuer?: string;
    /** Unix seconds used for `iat` (and the `exp` base). Default: now. */
    now?: number;
    /** Lifetime in seconds; `exp = now + expiresInSeconds`. Default 3600. */
    expiresInSeconds?: number;
    /** Optional `auth_time` claim (unix seconds) for session-binding contracts
     * (e.g. the gateway keys facade requires it). */
    authTime?: number;
    /** Optional `nbf` claim (unix seconds) for not-yet-valid negatives. */
    notBefore?: number;
    /**
     * Arbitrary PAYLOAD claim overrides, applied last: set any registered or
     * custom claim, or pass `undefined` as a value to OMIT a claim the other
     * options would have set (e.g. `{ exp: undefined }` mints a token with no
     * `exp`). Payload only — the protected header stays
     * `{ alg: "RS256", kid, typ: "JWT" }`; genuinely malformed shapes
     * (alg tampering, wrong-key signatures) are intentionally out of scope.
     */
    claims?: Record<string, unknown>;
}
export interface TestIdentityIssuer {
    /** The key id present in both the JWKS and every minted token header. */
    kid: string;
    /** The default `iss` of minted tokens — list it in `allowedIssuers`. */
    issuer: string;
    /** Public JWKS that verifies this kit's tokens (pass to `verifyIdentityJwt`). */
    jwks: JSONWebKeySet;
    /** The same JWKS as a JSON string (e.g. a `CAIL_IDENTITY_JWKS` env value). */
    jwksJson: string;
    /** Mint an RS256 identity JWT signed by this kit's private key. */
    mintIdentityJwt(options: MintTestIdentityJwtOptions): Promise<string>;
}
/**
 * Create an in-memory RS256 test identity issuer: a fresh keypair, its public
 * JWKS, and a `mintIdentityJwt` that signs identity JWTs verifiable with that
 * JWKS via `verifyIdentityJwt`. Defaults mint a VALID token (canonical
 * subject, canonical issuer); every payload claim can be overridden — typed
 * options for the common ones (`authTime`, `notBefore`, array `audience`)
 * plus arbitrary set/omit via `claims` — to drive the verifier's fail-closed
 * paths with tokens signed by a REAL key the JWKS advertises. What it will
 * never mint: `alg:"none"`, non-RS256 algorithms, or wrong-key signatures —
 * those are malformed by construction and stay consumer-local.
 *
 * Keys are generated per call and never persisted — nothing here is secret or
 * reusable outside the test process.
 */
export declare function createTestIdentityIssuer(options?: {
    kid?: string;
    issuer?: string;
}): Promise<TestIdentityIssuer>;
//# sourceMappingURL=testing.d.ts.map