/**
 * @cuny-ai-lab/cail-identity — the CAIL identity-JWT verifier.
 *
 * Pure async verifiers for gateway-signed CAIL identity JWTs. V1 accepts HS256
 * with a shared secret; V2 accepts RS256 with an in-memory public JWKS. Both
 * return a normalized identity, or `null` on ANY failure.
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

import { base64url, importJWK, jwtVerify, type JSONWebKeySet } from "jose";

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
export const CAIL_CANONICAL_ISSUER = "https://tools.ailab.gc.cuny.edu/cail-sso";
/** Staging issuer — list it in `allowedIssuers` to accept staging. */
export const CAIL_STAGING_ISSUER = "https://tools.cuny.qzz.io/cail-sso";

const encoder = new TextEncoder();
// fatal:true — RFC 7519 §7.2 / RFC 8725 §3.7 require the header and payload
// to be valid UTF-8 JSON. The default lenient decoder would smuggle invalid
// bytes through as U+FFFD instead of rejecting; fatal mode throws inside the
// existing try/catch, so malformed bytes fail closed to null.
const decoder = new TextDecoder("utf-8", { fatal: true });

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function ownProp(obj: Record<string, unknown>, key: string): unknown {
  return Object.hasOwn(obj, key) ? obj[key] : undefined;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

interface InspectedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
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
function inspectCailJwt(token: string): InspectedJwt | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const decoded: Uint8Array[] = [];
  try {
    for (const segment of parts) {
      if (!/^[A-Za-z0-9_-]*$/.test(segment)) return null;
      const bytes = base64url.decode(segment);
      if (base64url.encode(bytes) !== segment) return null;
      decoded.push(bytes);
    }

    const header: unknown = JSON.parse(decoder.decode(decoded[0]!));
    const payload: unknown = JSON.parse(decoder.decode(decoded[1]!));
    if (!isPlainObject(header) || !isPlainObject(payload)) return null;

    // Own-property checks prevent a polluted Object.prototype from supplying
    // security claims to a standards library that uses ordinary property reads.
    if (ownProp(header, "alg") !== "HS256") return null;
    if (Object.hasOwn(header, "crit")) return null;

    const exp = ownProp(payload, "exp");
    const aud = ownProp(payload, "aud");
    const iss = ownProp(payload, "iss");
    const nbf = ownProp(payload, "nbf");
    const sub = ownProp(payload, "sub");
    if (!isFiniteNumber(exp)) return null;
    if (aud !== "cail-internal") return null;
    if (typeof iss !== "string") return null;
    if (nbf !== undefined && !isFiniteNumber(nbf)) return null;
    if (typeof sub !== "string" || sub === "") return null;

    return { header, payload };
  } catch {
    return null;
  }
}

export async function verifyIdentityJwt(
  token: string,
  secret: string,
  opts?: VerifyOptions,
): Promise<CailIdentity | null> {
  if (typeof token !== "string" || typeof secret !== "string") return null;
  if (secret.length === 0) return null;
  // RFC 7518 §3.2: an HS256 key MUST be at least as large as the hash output
  // (256 bits = 32 bytes); RFC 8725 §3.5 / OWASP JWT cheat sheet: enforce
  // strong symmetric keys. Web Crypto happily imports ANY key length (jose
  // would refuse), so a misprovisioned deployment with a tiny secret would
  // otherwise verify fine — fail closed instead. Measured in UTF-8 BYTES,
  // not characters. (Production is `openssl rand -hex 32` = 64 bytes.)
  if (encoder.encode(secret).length < 32) return null;

  // `now`/`tol` are optional: `undefined` (or absent) means "use the default".
  // But a PRESENT non-finite value (NaN, ±Infinity) is caller-supplied garbage
  // that would silently disable the exp/nbf checks (`NaN <= x` is always false),
  // so it fails closed to null rather than accepting every token.
  let now: number;
  if (opts && opts.now !== undefined) {
    if (!isFiniteNumber(opts.now)) return null;
    now = opts.now;
  } else {
    now = Math.floor(Date.now() / 1000);
  }

  let tol: number;
  if (opts && opts.clockToleranceSeconds !== undefined) {
    if (!isFiniteNumber(opts.clockToleranceSeconds)) return null;
    tol = opts.clockToleranceSeconds;
  } else {
    tol = 60;
  }

  const inspected = inspectCailJwt(token);
  if (!inspected) return null;

  // I8 — an absent/empty allowlist rejects all tokens before verification.
  const allowedIssuers =
    opts && Array.isArray(opts.allowedIssuers)
      ? opts.allowedIssuers.filter(
          (issuer): issuer is string => typeof issuer === "string",
        )
      : [];
  if (allowedIssuers.length === 0) return null;

  let payload: Record<string, unknown>;
  try {
    const verified = await jwtVerify(token, encoder.encode(secret), {
      algorithms: ["HS256"],
      audience: "cail-internal",
      issuer: allowedIssuers,
      requiredClaims: ["exp", "sub"],
      clockTolerance: tol,
      currentDate: new Date(now * 1000),
    });
    payload = verified.payload as Record<string, unknown>;
  } catch {
    return null;
  }

  // Keep the inspected own-property values authoritative. `jwtVerify` owns
  // cryptography and registered-claim validation; CAIL owns its output shape.
  const sub = ownProp(inspected.payload, "sub") as string;

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
      ? entitlements.filter((e): e is string => typeof e === "string")
      : [],
  };
}

export interface VerifyIdentityJwtV2Options {
  /** Required audience value. The token audience may be a scalar or array. */
  expectedAudience: string;
  /** Required exact-match issuer allowlist. */
  allowedIssuers: string[];
  /** Unix seconds "now". Default: Math.floor(Date.now() / 1000). */
  now?: number;
  /** Symmetric clock leeway in seconds. Default 60. */
  clockToleranceSeconds?: number;
}

function isCanonicalBase64url(value: unknown): value is string {
  if (typeof value !== "string" || value === "") return false;
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return false;
  try {
    return base64url.encode(base64url.decode(value)) === value;
  } catch {
    return false;
  }
}

function inspectCailJwtV2(token: string): InspectedJwt | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const decoded: Uint8Array[] = [];
  try {
    for (const segment of parts) {
      if (!isCanonicalBase64url(segment)) return null;
      decoded.push(base64url.decode(segment));
    }

    const header: unknown = JSON.parse(decoder.decode(decoded[0]!));
    const payload: unknown = JSON.parse(decoder.decode(decoded[1]!));
    if (!isPlainObject(header) || !isPlainObject(payload)) return null;
    if (ownProp(header, "alg") !== "RS256") return null;
    const kid = ownProp(header, "kid");
    if (typeof kid !== "string" || kid === "") return null;
    if (Object.hasOwn(header, "crit")) return null;

    return { header, payload };
  } catch {
    return null;
  }
}

function isUniqueNonemptyStringArray(value: unknown): value is string[] {
  if (!Array.isArray(value) || value.length === 0) return false;
  if (!value.every((item) => typeof item === "string" && item !== "")) {
    return false;
  }
  return new Set(value).size === value.length;
}

function hasExpectedAudience(value: unknown, expected: string): boolean {
  if (typeof value === "string") return value !== "" && value === expected;
  return isUniqueNonemptyStringArray(value) && value.includes(expected);
}

function isRsaVerificationJwkForKid(
  value: Record<string, unknown>,
  kid: string,
): boolean {
  if (ownProp(value, "kty") !== "RSA" || ownProp(value, "kid") !== kid) {
    return false;
  }

  const alg = ownProp(value, "alg");
  if (alg !== undefined && alg !== "RS256") return false;
  const use = ownProp(value, "use");
  if (use !== undefined && use !== "sig") return false;
  const keyOps = ownProp(value, "key_ops");
  if (
    keyOps !== undefined &&
    (!isUniqueNonemptyStringArray(keyOps) || !keyOps.includes("verify"))
  ) {
    return false;
  }
  if (
    ["d", "p", "q", "dp", "dq", "qi"].some((name) =>
      Object.hasOwn(value, name),
    )
  ) {
    return false;
  }

  return (
    isCanonicalBase64url(ownProp(value, "n")) &&
    isCanonicalBase64url(ownProp(value, "e"))
  );
}

async function verifyIdentityJwtV2Internal(
  token: string,
  jwks: JSONWebKeySet,
  opts: VerifyIdentityJwtV2Options,
): Promise<CailIdentity | null> {
  if (typeof token !== "string" || !isPlainObject(jwks) || !isPlainObject(opts)) {
    return null;
  }

  const expectedAudience = ownProp(opts, "expectedAudience");
  const allowedIssuers = ownProp(opts, "allowedIssuers");
  if (typeof expectedAudience !== "string" || expectedAudience === "") {
    return null;
  }
  if (!isUniqueNonemptyStringArray(allowedIssuers)) return null;

  const nowOption = ownProp(opts, "now");
  const now =
    nowOption === undefined ? Math.floor(Date.now() / 1000) : nowOption;
  if (!isFiniteNumber(now)) return null;

  const toleranceOption = ownProp(opts, "clockToleranceSeconds");
  const tolerance = toleranceOption === undefined ? 60 : toleranceOption;
  if (!isFiniteNumber(tolerance) || tolerance < 0) return null;

  const keys = ownProp(jwks, "keys");
  if (
    !Array.isArray(keys) ||
    !keys.every((key): key is Record<string, unknown> => isPlainObject(key))
  ) {
    return null;
  }

  const inspected = inspectCailJwtV2(token);
  if (!inspected) return null;

  const kid = ownProp(inspected.header, "kid") as string;
  const candidates = keys.filter((key) =>
    isRsaVerificationJwkForKid(key, kid),
  );
  if (candidates.length !== 1) return null;

  const exp = ownProp(inspected.payload, "exp");
  const aud = ownProp(inspected.payload, "aud");
  const iss = ownProp(inspected.payload, "iss");
  const nbf = ownProp(inspected.payload, "nbf");
  const sub = ownProp(inspected.payload, "sub");
  if (!isFiniteNumber(exp)) return null;
  if (!hasExpectedAudience(aud, expectedAudience)) return null;
  if (
    typeof iss !== "string" ||
    iss === "" ||
    !allowedIssuers.includes(iss)
  ) {
    return null;
  }
  if (nbf !== undefined && !isFiniteNumber(nbf)) return null;
  if (typeof sub !== "string" || sub === "") return null;

  try {
    const key = await importJWK(candidates[0]!, "RS256");
    if (key instanceof Uint8Array || key.type !== "public") return null;
    await jwtVerify(token, key, {
      algorithms: ["RS256"],
      audience: expectedAudience,
      issuer: allowedIssuers,
      requiredClaims: ["exp", "sub"],
      clockTolerance: tolerance,
      currentDate: new Date(now * 1000),
    });
  } catch {
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
      ? entitlements.filter((item): item is string => typeof item === "string")
      : [],
  };
}

/**
 * Verify a CAIL RS256 identity JWT against an in-memory public JWKS.
 * Any malformed, unauthorized, unsupported, or ambiguous input returns null.
 */
export async function verifyIdentityJwtV2(
  token: string,
  jwks: JSONWebKeySet,
  opts: VerifyIdentityJwtV2Options,
): Promise<CailIdentity | null> {
  try {
    return await verifyIdentityJwtV2Internal(token, jwks, opts);
  } catch {
    return null;
  }
}
