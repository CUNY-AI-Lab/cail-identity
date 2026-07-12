/**
 * @cuny-ai-lab/cail-identity — the CAIL identity-JWT verifier.
 *
 * A single pure async function that verifies the gateway-signed CAIL identity
 * JWT (HS256) and returns a normalized identity, or `null` on ANY failure.
 *
 * Design contract (see README + CAIL_IDENTITY_PRIMITIVE_SPEC.md):
 *   - Pure Web Crypto only (crypto.subtle, TextEncoder, atob/btoa). Runs
 *     unchanged in Cloudflare Workers and Node >=20.
 *   - Algorithm is PINNED to HS256 in code; the token never chooses it.
 *   - `secret` is a function argument — never stored, never logged.
 *   - Fail closed: any ambiguity returns `null`. Never throws, never reveals a
 *     failure reason (no oracle).
 *   - Identity comes ONLY from a validly-signed token — no header trust, no
 *     subject derivation.
 */
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
/**
 * UTF-8 encode into an ArrayBuffer-backed Uint8Array. Web Crypto's
 * `BufferSource` requires an `ArrayBuffer` (not `SharedArrayBuffer`) view;
 * `TextEncoder.encode` is typed with the wider `ArrayBufferLike`, so we copy
 * into a fresh `ArrayBuffer`. Runtime-identical on Workers and Node.
 */
function utf8Bytes(str) {
    const src = encoder.encode(str);
    const out = new Uint8Array(new ArrayBuffer(src.length));
    out.set(src);
    return out;
}
function base64UrlDecode(segment) {
    // Reject anything that isn't strict base64url (atob is lax and would accept
    // stray "+"/"/"; the whole point of I2 is that the segment IS base64url).
    if (typeof segment !== "string" || !/^[A-Za-z0-9_-]*$/.test(segment)) {
        return null;
    }
    try {
        const converted = segment.replace(/-/g, "+").replace(/_/g, "/");
        const padded = converted + "=".repeat((4 - (converted.length % 4)) % 4);
        const binary = atob(padded);
        // Canonicality (RFC 4648 §3.5: trailing padding bits MUST be zero).
        // atob implements forgiving-base64 and silently drops non-zero trailing
        // bits, which would make the token STRING malleable — many encodings of
        // the same signature bytes, all verifying. Re-encode and compare: a
        // canonical segment round-trips byte-identically; anything else is null.
        if (btoa(binary) !== padded)
            return null;
        // Allocate a standalone ArrayBuffer so the view is ArrayBuffer-backed
        // (not SharedArrayBuffer), which crypto.subtle's BufferSource requires.
        const bytes = new Uint8Array(new ArrayBuffer(binary.length));
        for (let i = 0; i < binary.length; i++)
            bytes[i] = binary.charCodeAt(i);
        return bytes;
    }
    catch {
        return null;
    }
}
function isPlainObject(value) {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}
function ownProp(obj, key) {
    return Object.hasOwn(obj, key) ? obj[key] : undefined;
}
function isFiniteNumber(value) {
    return typeof value === "number" && Number.isFinite(value);
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
    // I1 — structure: exactly three dot-separated parts.
    const parts = token.split(".");
    if (parts.length !== 3)
        return null;
    const headerB64 = parts[0];
    const payloadB64 = parts[1];
    const signatureB64 = parts[2];
    // I2 — encoding: every segment is valid base64url.
    const headerBytes = base64UrlDecode(headerB64);
    const payloadBytes = base64UrlDecode(payloadB64);
    const signature = base64UrlDecode(signatureB64);
    if (!headerBytes || !payloadBytes || !signature)
        return null;
    // I3 — JSON: header and payload parse to JSON *objects*.
    let header;
    let payload;
    try {
        header = JSON.parse(decoder.decode(headerBytes));
        payload = JSON.parse(decoder.decode(payloadBytes));
    }
    catch {
        return null;
    }
    if (!isPlainObject(header) || !isPlainObject(payload))
        return null;
    // I4 — alg pinned. Never read alg from the token to CHOOSE the algorithm;
    // it may only equal the one hard-coded value.
    if (ownProp(header, "alg") !== "HS256")
        return null;
    // I4b — crit rejection. RFC 7515 §4.1.11: `crit` names header extensions
    // the verifier MUST understand and process; this verifier implements none,
    // so ANY header carrying its own `crit` member is rejected. (The gateway
    // never sets it — this closes the conformance gap, not a live hole.)
    if (Object.hasOwn(header, "crit"))
        return null;
    // I5 — signature: HMAC-SHA256 over "<headerB64>.<payloadB64>", constant-time.
    const key = await crypto.subtle.importKey("raw", utf8Bytes(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const valid = await crypto.subtle.verify("HMAC", key, signature, utf8Bytes(`${headerB64}.${payloadB64}`));
    if (!valid)
        return null;
    const exp = ownProp(payload, "exp");
    const aud = ownProp(payload, "aud");
    const iss = ownProp(payload, "iss");
    const nbf = ownProp(payload, "nbf");
    const sub = ownProp(payload, "sub");
    // I6 — exp required; reject only when exp <= now - tol (valid through exp+tol).
    if (!isFiniteNumber(exp) || exp <= now - tol)
        return null;
    // I7 — aud exact.
    if (aud !== "cail-internal")
        return null;
    // I8 — iss EXACT-match against a configured allowlist (NOT suffix, NOT
    // substring). Absent/empty allowlist rejects ALL tokens (fail closed).
    const allowedIssuers = opts && Array.isArray(opts.allowedIssuers) ? opts.allowedIssuers : [];
    if (typeof iss !== "string" || !allowedIssuers.includes(iss))
        return null;
    // I9 — nbf: if present, must be a finite number and not in the future past tol.
    if (nbf !== undefined) {
        if (!isFiniteNumber(nbf) || nbf > now + tol)
            return null;
    }
    // I10 — sub non-empty string.
    if (typeof sub !== "string" || sub === "")
        return null;
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
