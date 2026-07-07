/**
 * Test fixtures and the dependency-free REFERENCE READER.
 *
 * Two independent oracles guard the impl under test:
 *   1. `jose` (an audited third-party JWT lib) mints the VALID tokens, so we
 *      never sign with our own signer to check our own verifier.
 *   2. `referenceAccept()` below recomputes accept/reject straight from the
 *      raw claims + the I1..I10 rules, so the suite is not merely asserting
 *      against the implementation it is testing.
 */

import { SignJWT, base64url } from "jose";

export const SECRET = "S-the-known-test-secret";
export const WRONG_SECRET = "not-the-secret";
export const NOW = 1_000_000;
export const DEFAULT_TOL = 60;

const enc = new TextEncoder();
const keyOf = (s: string) => enc.encode(s);

/** Mint a valid HS256 token with jose. Claims are passed verbatim. */
export async function mintWithJose(
  claims: Record<string, unknown>,
  secret: string = SECRET,
): Promise<string> {
  // We intentionally set the raw claims ourselves rather than using jose's
  // setExpirationTime helpers, so the vector table controls exact numbers.
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .sign(keyOf(secret));
}

/** Mint a token with a DIFFERENT (still-symmetric) HMAC alg under a VALID
 * signature for that alg, using the real secret. This is the teeth of the
 * alg-confusion test: an alg-agile verifier that reads the alg from the token
 * would accept this; a properly HS256-pinned verifier rejects it at I4. */
export async function mintHmacAlg(
  alg: "HS384" | "HS512",
  claims: Record<string, unknown>,
  secret: string = SECRET,
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg, typ: "JWT" })
    .sign(keyOf(secret));
}

/** b64url-encode a UTF-8 string (used to hand-craft malformed segments). */
export function b64urlStr(s: string): string {
  return base64url.encode(enc.encode(s));
}

/**
 * Mint a token whose HEADER stamps an arbitrary `alg` label but whose SIGNATURE
 * is a genuinely-VALID HMAC over the chosen `hmacHash` (default SHA-256) using
 * the real secret. This DECOUPLES the header alg label from the actual hash.
 *
 * This is the vector that isolates I4: with `headerAlg:"HS384"` and
 * `hmacHash:"SHA-256"`, the SHA-256 signature verifies (I5 passes), so the ONLY
 * thing standing between this token and acceptance is the I4 alg pin. Remove I4
 * and the token flips to accepted. jose's SignJWT ties header.alg to the hash,
 * so we sign the signing-input directly with Web Crypto instead.
 */
export async function signWithHeaderAlg(
  claims: Record<string, unknown>,
  headerAlg: string,
  hmacHash: "SHA-256" | "SHA-384" | "SHA-512" = "SHA-256",
  secret: string = SECRET,
): Promise<string> {
  const headerB64 = base64url.encode(
    enc.encode(JSON.stringify({ alg: headerAlg, typ: "JWT" })),
  );
  const payloadB64 = base64url.encode(enc.encode(JSON.stringify(claims)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const key = await crypto.subtle.importKey(
    "raw",
    keyOf(secret),
    { name: "HMAC", hash: hmacHash },
    false,
    ["sign"],
  );
  const sig = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, enc.encode(signingInput)),
  );
  return `${signingInput}.${base64url.encode(sig)}`;
}

/** Hand-craft a token with an arbitrary header object, valid-looking payload,
 * and a bogus (non-verifying) signature. Used for alg-confusion fixtures where
 * the signature must NOT verify anyway (I4 rejects before I5, but we still want
 * a realistic shape). */
export function craftUnsigned(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  sig = "AAAA",
): string {
  return `${b64urlStr(JSON.stringify(header))}.${b64urlStr(
    JSON.stringify(payload),
  )}.${sig}`;
}

/** Take a valid jose-signed token and flip one byte of the payload segment,
 * keeping it valid base64url but breaking the signature (I5). */
export function tamperPayloadByte(token: string): string {
  const [h, p, s] = token.split(".");
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const chars = p!.split("");
  // flip the first char to a different base64url char
  const cur = chars[0]!;
  chars[0] = cur === "A" ? "B" : "A";
  return `${h}.${chars.join("")}.${s}`;
}

// ---------------------------------------------------------------------------
// REFERENCE READER — dependency-free re-derivation of accept/reject.
// This deliberately mirrors the SPEC prose, not the impl code, so a bug that
// exists in both would have to be independently written twice.
// ---------------------------------------------------------------------------

export interface RefResult {
  accept: boolean;
  identity?: {
    subject: string;
    email?: string;
    name?: string;
    entitlements: string[];
  };
}

function isB64Url(seg: string): boolean {
  return /^[A-Za-z0-9_-]*$/.test(seg);
}

function decodeJson(seg: string): unknown | typeof INVALID {
  if (!isB64Url(seg)) return INVALID;
  try {
    const bytes = base64url.decode(seg);
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return INVALID;
  }
}

const INVALID = Symbol("invalid");

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Recompute the expected result from the RAW token + rules, independently of
 * the impl. `sigValid` is supplied by the caller because signature checking
 * needs the secret/crypto; the reference reader takes the crypto verdict as an
 * input and re-derives everything else.
 */
export function referenceAccept(
  token: string,
  sigValid: boolean,
  now: number,
  tol: number,
  allowedIssuers: string[],
): RefResult {
  const parts = token.split(".");
  if (parts.length !== 3) return { accept: false }; // I1
  const [h, p] = parts;

  const header = decodeJson(h!); // I2 + I3
  const payload = decodeJson(p!);
  if (header === INVALID || payload === INVALID) return { accept: false };
  if (!isPlainObject(header) || !isPlainObject(payload))
    return { accept: false }; // I3

  if (header.alg !== "HS256") return { accept: false }; // I4
  if (!sigValid) return { accept: false }; // I5

  const { exp, aud, iss, nbf, sub } = payload;
  if (typeof exp !== "number" || exp <= now - tol) return { accept: false }; // I6
  if (aud !== "cail-internal") return { accept: false }; // I7
  if (typeof iss !== "string" || !allowedIssuers.includes(iss))
    return { accept: false }; // I8 — exact allowlist, fail closed if empty
  if (nbf !== undefined) {
    if (typeof nbf !== "number" || nbf > now + tol) return { accept: false }; // I9
  }
  if (typeof sub !== "string" || sub === "") return { accept: false }; // I10

  return {
    accept: true,
    identity: {
      subject: sub,
      email: typeof payload.email === "string" ? payload.email : undefined,
      name: typeof payload.name === "string" ? payload.name : undefined,
      entitlements: Array.isArray(payload.entitlements)
        ? (payload.entitlements.filter(
            (e) => typeof e === "string",
          ) as string[])
        : [],
    },
  };
}
