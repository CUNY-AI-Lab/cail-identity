import {
  CompactSign,
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
  claims: Record<string, unknown>,
  fixture: RsaFixture,
  header: Record<string, unknown> = {},
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: fixture.kid, ...header })
    .sign(fixture.privateKey);
}

export async function signRawRsaPayload(
  payload: Uint8Array,
  fixture: RsaFixture,
): Promise<string> {
  return new CompactSign(payload)
    .setProtectedHeader({ alg: "RS256", kid: fixture.kid })
    .sign(fixture.privateKey);
}

export function encodeJson(value: unknown): string {
  return base64url.encode(new TextEncoder().encode(JSON.stringify(value)));
}
