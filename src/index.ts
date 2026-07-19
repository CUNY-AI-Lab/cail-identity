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

import { base64url, importJWK, jwtVerify, type JSONWebKeySet } from "jose";

export interface CailIdentity {
  subject: string;
  email?: string;
  name?: string;
  entitlements: string[];
}

/** Stable pseudonymous identifier shared across CAIL applications. */
export const CAIL_SUBJECT_PATTERN = /^cail-[0-9a-f]{32}$/;

/** True only for the canonical stable CAIL subject representation. */
export function isCailSubject(value: unknown): value is string {
  return typeof value === "string" && CAIL_SUBJECT_PATTERN.test(value);
}

const CUNY_LOGIN_REALM = "@LOGIN.CUNY.EDU";
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/;
// ASCII whitespace only — the exact set LuaJIT's `%s` pattern trims in the gate
// (space, tab, newline, vertical tab, form feed, carriage return).
const ASCII_WHITESPACE = /^[ \t\n\v\f\r]+|[ \t\n\v\f\r]+$/g;
const encoder = new TextEncoder();

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
export function canonicalizeCunySubject(subject: string): string {
  if (typeof subject !== "string") {
    throw new TypeError("CUNY OIDC subject must be a string.");
  }
  // Trim edge ASCII whitespace first (a trailing newline is trimmed, as the
  // gate does), then fail closed on any interior control character.
  const trimmed = subject.replace(ASCII_WHITESPACE, "");
  if (CONTROL_CHARACTER.test(trimmed)) {
    throw new TypeError("CUNY OIDC subject must not contain control characters.");
  }
  let canonical = trimmed.replace(/[a-z]/g, (ch) => ch.toUpperCase());
  if (canonical.endsWith(CUNY_LOGIN_REALM)) {
    canonical = canonical.slice(0, -CUNY_LOGIN_REALM.length);
  }
  if (canonical === "") {
    throw new TypeError("CUNY OIDC subject must not be empty.");
  }
  return canonical;
}

export interface DeriveCailSubjectOptions {
  /** Exact trusted OIDC issuer; it namespaces otherwise identical subjects. */
  issuer: string;
  /** Subject returned by the trusted CUNY OIDC provider. */
  oidcSubject: string;
  /** Secret stable salt, supplied only at the identity/authentication boundary. */
  subjectSalt: string;
}

function bytesToHex(bytes: Uint8Array): string {
  let result = "";
  for (const byte of bytes) result += byte.toString(16).padStart(2, "0");
  return result;
}

/**
 * Derive the established stable pseudonymous CAIL subject.
 *
 * `cail-` + the first 32 hexadecimal characters of
 * HMAC-SHA256(subjectSalt, `${issuer}|${canonicalSubject}`).
 */
export async function deriveCailSubject(
  options: DeriveCailSubjectOptions,
): Promise<string> {
  if (
    typeof options !== "object" ||
    options === null ||
    typeof options.issuer !== "string" ||
    options.issuer === "" ||
    CONTROL_CHARACTER.test(options.issuer)
  ) {
    throw new TypeError("issuer must be a non-empty string without controls.");
  }
  if (
    typeof options.subjectSalt !== "string" ||
    options.subjectSalt === "" ||
    CONTROL_CHARACTER.test(options.subjectSalt)
  ) {
    throw new TypeError(
      "subjectSalt must be a non-empty string without controls.",
    );
  }

  const canonical = canonicalizeCunySubject(options.oidcSubject);
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(options.subjectSalt),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(
    await crypto.subtle.sign(
      "HMAC",
      key,
      encoder.encode(`${options.issuer}|${canonical}`),
    ),
  );
  return `cail-${bytesToHex(digest).slice(0, 32)}`;
}

/** Canonical production issuer — list it in `allowedIssuers` to accept prod. */
export const CAIL_CANONICAL_ISSUER = "https://tools.ailab.gc.cuny.edu/cail-sso";
/** Staging issuer — list it in `allowedIssuers` to accept staging. */
export const CAIL_STAGING_ISSUER = "https://tools.cuny.qzz.io/cail-sso";

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

function isCanonicalBase64url(value: unknown): value is string {
  if (typeof value !== "string" || value === "") return false;
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return false;
  try {
    return base64url.encode(base64url.decode(value)) === value;
  } catch {
    return false;
  }
}

function inspectCailJwt(token: string): InspectedJwt | null {
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

function hasExactAudience(value: unknown, expected: string): boolean {
  return typeof value === "string" && value !== "" && value === expected;
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

async function verifyIdentityJwtInternal(
  token: string,
  jwks: JSONWebKeySet,
  opts: VerifyIdentityJwtOptions,
): Promise<CailIdentity | null> {
  if (typeof token !== "string" || !isPlainObject(jwks) || !isPlainObject(opts)) {
    return null;
  }

  const expectedAudience = ownProp(opts, "expectedAudience");
  const allowedIssuers = ownProp(opts, "allowedIssuers");
  if (typeof expectedAudience !== "string" || expectedAudience === "") {
    return null;
  }
  if (
    !isUniqueNonemptyStringArray(allowedIssuers) ||
    allowedIssuers.length !== 1
  ) {
    return null;
  }
  const expectedIssuer = allowedIssuers[0]!;

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

  const inspected = inspectCailJwt(token);
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
  if (!hasExactAudience(aud, expectedAudience)) return null;
  if (
    typeof iss !== "string" ||
    iss === "" ||
    iss !== expectedIssuer
  ) {
    return null;
  }
  if (nbf !== undefined && !isFiniteNumber(nbf)) return null;
  if (!isCailSubject(sub)) return null;

  try {
    const key = await importJWK(candidates[0]!, "RS256");
    if (key instanceof Uint8Array || key.type !== "public") return null;
    await jwtVerify(token, key, {
      algorithms: ["RS256"],
      audience: expectedAudience,
      issuer: expectedIssuer,
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
export async function verifyIdentityJwt(
  token: string,
  jwks: JSONWebKeySet,
  opts: VerifyIdentityJwtOptions,
): Promise<CailIdentity | null> {
  try {
    return await verifyIdentityJwtInternal(token, jwks, opts);
  } catch {
    return null;
  }
}
