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
import { base64url, importJWK, jwtVerify } from "jose";
/** Canonical production issuer — list it in `allowedIssuers` to accept prod. */
export const CAIL_CANONICAL_ISSUER = "https://tools.ailab.gc.cuny.edu/cail-sso";
/** Staging issuer — list it in `allowedIssuers` to accept staging. */
export const CAIL_STAGING_ISSUER = "https://tools.cuny.qzz.io/cail-sso";
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
function isCanonicalBase64url(value) {
    if (typeof value !== "string" || value === "")
        return false;
    if (!/^[A-Za-z0-9_-]+$/.test(value))
        return false;
    try {
        return base64url.encode(base64url.decode(value)) === value;
    }
    catch {
        return false;
    }
}
function inspectCailJwtV2(token) {
    const parts = token.split(".");
    if (parts.length !== 3)
        return null;
    const decoded = [];
    try {
        for (const segment of parts) {
            if (!isCanonicalBase64url(segment))
                return null;
            decoded.push(base64url.decode(segment));
        }
        const header = JSON.parse(decoder.decode(decoded[0]));
        const payload = JSON.parse(decoder.decode(decoded[1]));
        if (!isPlainObject(header) || !isPlainObject(payload))
            return null;
        if (ownProp(header, "alg") !== "RS256")
            return null;
        const kid = ownProp(header, "kid");
        if (typeof kid !== "string" || kid === "")
            return null;
        if (Object.hasOwn(header, "crit"))
            return null;
        return { header, payload };
    }
    catch {
        return null;
    }
}
function isUniqueNonemptyStringArray(value) {
    if (!Array.isArray(value) || value.length === 0)
        return false;
    if (!value.every((item) => typeof item === "string" && item !== "")) {
        return false;
    }
    return new Set(value).size === value.length;
}
function hasExpectedAudience(value, expected) {
    if (typeof value === "string")
        return value !== "" && value === expected;
    return isUniqueNonemptyStringArray(value) && value.includes(expected);
}
function isRsaVerificationJwkForKid(value, kid) {
    if (ownProp(value, "kty") !== "RSA" || ownProp(value, "kid") !== kid) {
        return false;
    }
    const alg = ownProp(value, "alg");
    if (alg !== undefined && alg !== "RS256")
        return false;
    const use = ownProp(value, "use");
    if (use !== undefined && use !== "sig")
        return false;
    const keyOps = ownProp(value, "key_ops");
    if (keyOps !== undefined &&
        (!isUniqueNonemptyStringArray(keyOps) || !keyOps.includes("verify"))) {
        return false;
    }
    if (["d", "p", "q", "dp", "dq", "qi"].some((name) => Object.hasOwn(value, name))) {
        return false;
    }
    return (isCanonicalBase64url(ownProp(value, "n")) &&
        isCanonicalBase64url(ownProp(value, "e")));
}
async function verifyIdentityJwtV2Internal(token, jwks, opts) {
    if (typeof token !== "string" || !isPlainObject(jwks) || !isPlainObject(opts)) {
        return null;
    }
    const expectedAudience = ownProp(opts, "expectedAudience");
    const allowedIssuers = ownProp(opts, "allowedIssuers");
    if (typeof expectedAudience !== "string" || expectedAudience === "") {
        return null;
    }
    if (!isUniqueNonemptyStringArray(allowedIssuers))
        return null;
    const nowOption = ownProp(opts, "now");
    const now = nowOption === undefined ? Math.floor(Date.now() / 1000) : nowOption;
    if (!isFiniteNumber(now))
        return null;
    const toleranceOption = ownProp(opts, "clockToleranceSeconds");
    const tolerance = toleranceOption === undefined ? 60 : toleranceOption;
    if (!isFiniteNumber(tolerance) || tolerance < 0)
        return null;
    const keys = ownProp(jwks, "keys");
    if (!Array.isArray(keys) ||
        !keys.every((key) => isPlainObject(key))) {
        return null;
    }
    const inspected = inspectCailJwtV2(token);
    if (!inspected)
        return null;
    const kid = ownProp(inspected.header, "kid");
    const candidates = keys.filter((key) => isRsaVerificationJwkForKid(key, kid));
    if (candidates.length !== 1)
        return null;
    const exp = ownProp(inspected.payload, "exp");
    const aud = ownProp(inspected.payload, "aud");
    const iss = ownProp(inspected.payload, "iss");
    const nbf = ownProp(inspected.payload, "nbf");
    const sub = ownProp(inspected.payload, "sub");
    if (!isFiniteNumber(exp))
        return null;
    if (!hasExpectedAudience(aud, expectedAudience))
        return null;
    if (typeof iss !== "string" ||
        iss === "" ||
        !allowedIssuers.includes(iss)) {
        return null;
    }
    if (nbf !== undefined && !isFiniteNumber(nbf))
        return null;
    if (typeof sub !== "string" || sub === "")
        return null;
    try {
        const key = await importJWK(candidates[0], "RS256");
        if (key instanceof Uint8Array || key.type !== "public")
            return null;
        await jwtVerify(token, key, {
            algorithms: ["RS256"],
            audience: expectedAudience,
            issuer: allowedIssuers,
            requiredClaims: ["exp", "sub"],
            clockTolerance: tolerance,
            currentDate: new Date(now * 1000),
        });
    }
    catch {
        return null;
    }
    const email = ownProp(inspected.payload, "email");
    const name = ownProp(inspected.payload, "name");
    const entitlements = ownProp(inspected.payload, "entitlements");
    return {
        subject: sub,
        email: typeof email === "string" ? email : undefined,
        name: typeof name === "string" ? name : undefined,
        entitlements: Array.isArray(entitlements)
            ? entitlements.filter((item) => typeof item === "string")
            : [],
    };
}
/**
 * Verify a CAIL RS256 identity JWT against an in-memory public JWKS.
 * Any malformed, unauthorized, unsupported, or ambiguous input returns null.
 */
export async function verifyIdentityJwtV2(token, jwks, opts) {
    try {
        return await verifyIdentityJwtV2Internal(token, jwks, opts);
    }
    catch {
        return null;
    }
}
