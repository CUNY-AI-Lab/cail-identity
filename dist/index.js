/**
 * @cuny-ai-lab/cail-identity — the CAIL identity-JWT verifier.
 *
 * A single pure async function that verifies the gateway-signed CAIL identity
 * JWT (HS256) and returns a normalized identity, or `null` on ANY failure.
 *
 * Design contract (see README):
 *   - JOSE/JWT protocol machinery is delegated to `jose`, which uses the same
 *     Web Crypto APIs across Cloudflare Workers, browsers, Bun, and Node >=20.
 *   - Algorithm is PINNED to HS256 in code; the token never chooses it.
 *   - `secret` is a function argument — never stored, never logged.
 *   - Fail closed: any ambiguity returns `null`. Never throws, never reveals a
 *     failure reason (no oracle).
 *   - Identity comes ONLY from a validly-signed token — no header trust, no
 *     subject derivation.
 */
import { base64url, jwtVerify } from "jose";
/** Canonical production issuer — list it in `allowedIssuers` to accept prod. */
export const CAIL_CANONICAL_ISSUER = "https://tools.ailab.gc.cuny.edu/cail-sso";
/** Staging issuer — list it in `allowedIssuers` to accept staging. */
export const CAIL_STAGING_ISSUER = "https://tools.cuny.qzz.io/cail-sso";
const encoder = new TextEncoder();
// fatal:true — RFC 7519 §7.2 / RFC 8725 §3.7 require the header and payload
// to be valid UTF-8 JSON. The default lenient decoder would smuggle invalid
// bytes through as U+FFFD instead of rejecting; fatal mode throws inside the
// existing try/catch, so malformed bytes fail closed to null.
const decoder = new TextDecoder("utf-8", { fatal: true });
function isPlainObject(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}
function ownProp(obj, key) {
    return Object.hasOwn(obj, key) ? obj[key] : undefined;
}
function isFiniteNumber(value) {
    return typeof value === "number" && Number.isFinite(value);
}
/**
 * Apply the deliberately stricter parts of the CAIL token profile before
 * handing protocol verification to `jose`.
 *
 * `jose` accepts equivalent non-canonical base64url spellings and decodes JSON
 * with a non-fatal TextDecoder. It also follows the JWT standard in accepting
 * an audience array, while CAIL's v1 contract requires one exact scalar. These
 * checks preserve the established contract without reimplementing signatures,
 * time validation, or JOSE algorithm handling.
 */
function inspectCailJwt(token) {
    const parts = token.split(".");
    if (parts.length !== 3)
        return null;
    const decoded = [];
    try {
        for (const segment of parts) {
            if (!/^[A-Za-z0-9_-]*$/.test(segment))
                return null;
            const bytes = base64url.decode(segment);
            if (base64url.encode(bytes) !== segment)
                return null;
            decoded.push(bytes);
        }
        const header = JSON.parse(decoder.decode(decoded[0]));
        const payload = JSON.parse(decoder.decode(decoded[1]));
        if (!isPlainObject(header) || !isPlainObject(payload))
            return null;
        // Own-property checks prevent a polluted Object.prototype from supplying
        // security claims to a standards library that uses ordinary property reads.
        if (ownProp(header, "alg") !== "HS256")
            return null;
        if (Object.hasOwn(header, "crit"))
            return null;
        const exp = ownProp(payload, "exp");
        const aud = ownProp(payload, "aud");
        const iss = ownProp(payload, "iss");
        const nbf = ownProp(payload, "nbf");
        const sub = ownProp(payload, "sub");
        if (!isFiniteNumber(exp))
            return null;
        if (aud !== "cail-internal")
            return null;
        if (typeof iss !== "string")
            return null;
        if (nbf !== undefined && !isFiniteNumber(nbf))
            return null;
        if (typeof sub !== "string" || sub === "")
            return null;
        return { header, payload };
    }
    catch {
        return null;
    }
}
export async function verifyIdentityJwt(token, secret, opts) {
    if (typeof token !== "string" || typeof secret !== "string")
        return null;
    if (secret.length === 0)
        return null;
    // RFC 7518 §3.2: an HS256 key MUST be at least as large as the hash output
    // (256 bits = 32 bytes); RFC 8725 §3.5 / OWASP JWT cheat sheet: enforce
    // strong symmetric keys. Web Crypto happily imports ANY key length (jose
    // would refuse), so a misprovisioned deployment with a tiny secret would
    // otherwise verify fine — fail closed instead. Measured in UTF-8 BYTES,
    // not characters. (Production is `openssl rand -hex 32` = 64 bytes.)
    if (encoder.encode(secret).length < 32)
        return null;
    // `now`/`tol` are optional: `undefined` (or absent) means "use the default".
    // But a PRESENT non-finite value (NaN, ±Infinity) is caller-supplied garbage
    // that would silently disable the exp/nbf checks (`NaN <= x` is always false),
    // so it fails closed to null rather than accepting every token.
    let now;
    if (opts && opts.now !== undefined) {
        if (!isFiniteNumber(opts.now))
            return null;
        now = opts.now;
    }
    else {
        now = Math.floor(Date.now() / 1000);
    }
    let tol;
    if (opts && opts.clockToleranceSeconds !== undefined) {
        if (!isFiniteNumber(opts.clockToleranceSeconds))
            return null;
        tol = opts.clockToleranceSeconds;
    }
    else {
        tol = 60;
    }
    const inspected = inspectCailJwt(token);
    if (!inspected)
        return null;
    // I8 — an absent/empty allowlist rejects all tokens before verification.
    const allowedIssuers = opts && Array.isArray(opts.allowedIssuers)
        ? opts.allowedIssuers.filter((issuer) => typeof issuer === "string")
        : [];
    if (allowedIssuers.length === 0)
        return null;
    let payload;
    try {
        const verified = await jwtVerify(token, encoder.encode(secret), {
            algorithms: ["HS256"],
            audience: "cail-internal",
            issuer: allowedIssuers,
            requiredClaims: ["exp", "sub"],
            clockTolerance: tol,
            currentDate: new Date(now * 1000),
        });
        payload = verified.payload;
    }
    catch {
        return null;
    }
    // Keep the inspected own-property values authoritative. `jwtVerify` owns
    // cryptography and registered-claim validation; CAIL owns its output shape.
    const sub = ownProp(inspected.payload, "sub");
    // Output mapping. Unknown claims dropped; input never mutated.
    const email = ownProp(payload, "email");
    const name = ownProp(payload, "name");
    // Entitlements on a signature-VERIFIED token: a malformed claim — a
    // non-array value, or array members that are not strings — is coerced by
    // DROPPING the malformed parts (fail closed: privileges can only shrink,
    // never elevate). This is deliberate on both sides:
    //   - NOT a rejection: a gateway producer bug in the entitlements claim
    //     must degrade to "fewer privileges", never to total access loss for
    //     an otherwise-valid identity.
    //   - NOT logged/signaled: this primitive is pure (browser/Workers/Node,
    //     no console, no diagnostics surface) and its whole contract is
    //     "identity or null, minimal throwing" — there is no in-contract
    //     channel to report a claim anomaly, so visibility is the VERIFIED
    //     CONSUMER'S concern, not this verifier's.
    // Pinned by vectors V25/V25b/V25c (malformed entitlements filter to
    // strings / collapse to [] and never elevate).
    const entitlements = ownProp(payload, "entitlements");
    return {
        subject: sub,
        email: typeof email === "string" ? email : undefined,
        name: typeof name === "string" ? name : undefined,
        entitlements: Array.isArray(entitlements)
            ? entitlements.filter((e) => typeof e === "string")
            : [],
    };
}
