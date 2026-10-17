import {
  SignJWT,
  base64url,
  exportJWK,
  generateKeyPair,
  type CryptoKey,
  type JSONWebKeySet,
  type JWK,
} from "jose";

export interface RsaFixture {
  kid: string;
  privateKey: CryptoKey;
  publicJwk: JWK;
  jwks: JSONWebKeySet;
}

export type JsonValue =
  | boolean
  | null
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue }
  | undefined;
export type JsonObject = { [key: string]: JsonValue };

const BASE64URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export async function makeRsaFixture(kid: string): Promise<RsaFixture> {
  const { privateKey, publicKey } = await generateKeyPair("RS256", {
    extractable: true,
  });
  const publicJwk = {
    ...(await exportJWK(publicKey)),
    alg: "RS256",
    kid,
    key_ops: ["verify"],
    use: "sig",
  };
  return { kid, privateKey, publicJwk, jwks: { keys: [publicJwk] } };
}

export async function mintRsaJwt(
  claims: JsonObject,
  fixture: RsaFixture,
  header: JsonObject = {},
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: fixture.kid, ...header })
    .sign(fixture.privateKey);
}

/**
 * RS256-sign the exact signing input `<header>.<payload>` as given, so a
 * token whose segments the verifier must reject still carries a valid
 * signature and only the rule under test can reject it.
 */
export async function signSegments(
  headerSegment: string,
  payloadSegment: string,
  fixture: RsaFixture,
): Promise<string> {
  const signingInput = `${headerSegment}.${payloadSegment}`;
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    fixture.privateKey,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${base64url.encode(new Uint8Array(signature))}`;
}

export function encodeJson<Value>(value: Value): string {
  return base64url.encode(new TextEncoder().encode(JSON.stringify(value)));
}

/** Flip the lowest bit of the base64url character at `index`. */
export function flipLowBit(segment: string, index: number): string {
  const position = BASE64URL_ALPHABET.indexOf(segment.charAt(index));
  if (position === -1) throw new Error("index is outside the segment");
  return (
    segment.slice(0, index) +
    BASE64URL_ALPHABET.charAt(position ^ 1) +
    segment.slice(index + 1)
  );
}

/**
 * Spell a base64url segment non-canonically: flip a padding bit in its last
 * character, which leaves the decoded bytes unchanged.
 */
export function withPaddingBitSet(segment: string): string {
  if (segment.length % 4 === 0) {
    throw new Error("segment has no padding bits");
  }
  return flipLowBit(segment, segment.length - 1);
}
