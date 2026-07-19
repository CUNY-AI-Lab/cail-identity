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
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { CAIL_CANONICAL_ISSUER } from "./index.js";
// ---------------------------------------------------------------------------
// Deterministic canonical test subjects
// ---------------------------------------------------------------------------
/**
 * Synchronous SHA-256 (FIPS 180-4) over UTF-8 bytes, returning lowercase hex.
 *
 * Hand-rolled ON PURPOSE, for test-support only: `crypto.subtle.digest` is
 * async, and fixtures need subjects synchronously (module-level constants,
 * default parameter values). Correctness is pinned in the test suite against
 * FIPS vectors and `node:crypto` over arbitrary inputs. Never use this for
 * anything security-bearing — production subject derivation stays
 * `deriveCailSubject` (HMAC-SHA256 via Web Crypto).
 */
function sha256Hex(input) {
    const bytes = new TextEncoder().encode(input);
    const paddedLength = (((bytes.length + 8) >> 6) + 1) << 6;
    const padded = new Uint8Array(paddedLength);
    padded.set(bytes);
    padded[bytes.length] = 0x80;
    const view = new DataView(padded.buffer);
    // Message length in BITS as a 64-bit big-endian integer.
    view.setUint32(paddedLength - 8, Math.floor(bytes.length / 0x20000000));
    view.setUint32(paddedLength - 4, (bytes.length << 3) >>> 0);
    const k = SHA256_ROUND_CONSTANTS;
    const state = Uint32Array.from(SHA256_INITIAL_STATE);
    const w = new Uint32Array(64);
    const rotr = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;
    for (let offset = 0; offset < paddedLength; offset += 64) {
        for (let i = 0; i < 16; i++)
            w[i] = view.getUint32(offset + i * 4);
        for (let i = 16; i < 64; i++) {
            const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
            const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
        }
        let a = state[0];
        let b = state[1];
        let c = state[2];
        let d = state[3];
        let e = state[4];
        let f = state[5];
        let g = state[6];
        let h = state[7];
        for (let i = 0; i < 64; i++) {
            const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const ch = (e & f) ^ (~e & g);
            const t1 = (h + s1 + ch + k[i] + w[i]) >>> 0;
            const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const t2 = (s0 + maj) >>> 0;
            h = g;
            g = f;
            f = e;
            e = (d + t1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (t1 + t2) >>> 0;
        }
        state[0] = (state[0] + a) >>> 0;
        state[1] = (state[1] + b) >>> 0;
        state[2] = (state[2] + c) >>> 0;
        state[3] = (state[3] + d) >>> 0;
        state[4] = (state[4] + e) >>> 0;
        state[5] = (state[5] + f) >>> 0;
        state[6] = (state[6] + g) >>> 0;
        state[7] = (state[7] + h) >>> 0;
    }
    let hex = "";
    for (const word of state)
        hex += word.toString(16).padStart(8, "0");
    return hex;
}
const SHA256_INITIAL_STATE = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19,
];
// prettier-ignore
const SHA256_ROUND_CONSTANTS = Uint32Array.from([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
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
export function canonicalTestSubject(seed) {
    if (typeof seed !== "string") {
        throw new TypeError("canonicalTestSubject seed must be a string.");
    }
    return `cail-${sha256Hex(seed).slice(0, 32)}`;
}
/**
 * Ready-made canonical test subjects for the common case. All distinct, all
 * matching `CAIL_SUBJECT_PATTERN`, each equal to
 * `canonicalTestSubject(<name>)`.
 */
export const TEST_SUBJECTS = {
    alice: canonicalTestSubject("alice"),
    bob: canonicalTestSubject("bob"),
    carol: canonicalTestSubject("carol"),
};
/**
 * Create an in-memory RS256 test identity issuer: a fresh keypair, its public
 * JWKS, and a `mintIdentityJwt` that signs identity JWTs verifiable with that
 * JWKS via `verifyIdentityJwt`. Defaults mint a VALID token (canonical
 * subject, canonical issuer); every claim can be overridden to drive the
 * verifier's fail-closed paths.
 *
 * Keys are generated per call and never persisted — nothing here is secret or
 * reusable outside the test process.
 */
export async function createTestIdentityIssuer(options) {
    const kid = options?.kid ?? "cail-test-identity-key";
    const issuer = options?.issuer ?? CAIL_CANONICAL_ISSUER;
    const { privateKey, publicKey } = await generateKeyPair("RS256", {
        extractable: true,
    });
    const publicJwk = {
        ...(await exportJWK(publicKey)),
        alg: "RS256",
        kid,
        use: "sig",
        key_ops: ["verify"],
    };
    const jwks = { keys: [publicJwk] };
    return {
        kid,
        issuer,
        jwks,
        jwksJson: JSON.stringify(jwks),
        async mintIdentityJwt(mint) {
            if (typeof mint !== "object" || mint === null) {
                throw new TypeError("mintIdentityJwt requires an options object.");
            }
            if (typeof mint.audience !== "string" || mint.audience === "") {
                throw new TypeError("mintIdentityJwt requires a non-empty `audience` (the `aud` your verifier expects).");
            }
            const now = mint.now ?? Math.floor(Date.now() / 1000);
            const jwt = new SignJWT({
                ...(mint.email !== undefined ? { email: mint.email } : {}),
                ...(mint.name !== undefined ? { name: mint.name } : {}),
                ...(mint.entitlements !== undefined
                    ? { entitlements: mint.entitlements }
                    : {}),
            })
                .setProtectedHeader({ alg: "RS256", kid, typ: "JWT" })
                .setIssuer(mint.issuer ?? issuer)
                .setAudience(mint.audience)
                .setSubject(mint.subject ?? TEST_SUBJECTS.alice)
                .setIssuedAt(now)
                .setExpirationTime(now + (mint.expiresInSeconds ?? 3600));
            return jwt.sign(privateKey);
        },
    };
}
