import { beforeAll, describe, expect, it } from "vitest";
import { SignJWT, base64url } from "jose";
import {
  loadIdentityVerifierConfig,
  verifyIdentityJwt,
  type LoadIdentityVerifierConfigInput,
} from "../src/index.js";
import {
  createTestIdentityIssuer,
  type TestIdentityIssuer,
} from "../src/testing.js";
import {
  encodeJson,
  makeRsaFixture,
  mintRsaJwt,
  signRawRsaPayload,
  type JsonObject,
  type JsonValue,
  type RsaFixture,
} from "./fixtures.js";
import { stringFrom, unknownArrayFrom } from "../src/validation.js";

const NOW = 1_000_000;
const ISS = "https://issuer.example/cail-sso";
const OTHER_ISS = "https://other-issuer.example/cail-sso";
const AUD = "cail-internal";
const OPTS = { expectedAudience: AUD, allowedIssuers: [ISS], now: NOW };

let oldKey: RsaFixture;
let newKey: RsaFixture;
let testIssuer: TestIdentityIssuer;

beforeAll(async () => {
  [testIssuer, oldKey, newKey] = await Promise.all([
    createTestIdentityIssuer({ issuer: ISS, kid: "issuer-2026-08" }),
    makeRsaFixture("old-2026-07"),
    makeRsaFixture("new-2026-08"),
  ]);
});

function claims(over: JsonObject = {}): JsonObject {
  return {
    sub: "cail-0123456789abcdef0123456789abcdef",
    aud: AUD,
    iss: ISS,
    exp: NOW + 3600,
    ...over,
  };
}

async function mint(value: JsonObject = claims()): Promise<string> {
  return testIssuer.mintIdentityJwt({
    audience: AUD,
    now: NOW,
    claims: {
      aud: undefined,
      exp: undefined,
      iat: undefined,
      iss: undefined,
      sub: undefined,
      ...value,
    },
  });
}

type VerifyOptions = {
  allowedIssuers?: JsonValue;
  expectedAudience?: JsonValue;
  now?: JsonValue;
  clockToleranceSeconds?: JsonValue;
};

async function verify<Token extends string, Jwks>(
  token: Token,
  jwks?: Jwks,
  opts?: VerifyOptions,
) {
  const jwksValue = jwks === undefined ? testIssuer.jwks : jwks;
  const values: VerifyOptions = opts ?? OPTS;
  const allowedIssuers = values.allowedIssuers;
  const allowedIssuerArray = unknownArrayFrom(allowedIssuers);
  const issuer =
    allowedIssuerArray === undefined
      ? undefined
      : stringFrom(allowedIssuerArray[0]);
  const raw = {
    jwks: JSON.stringify(jwksValue),
    issuer,
    expectedAudience: values.expectedAudience,
    supportedIssuers: allowedIssuers,
    now: values.now,
    clockToleranceSeconds: values.clockToleranceSeconds,
  };
  // SAFETY: this test helper deliberately forwards malformed JSON-shaped
  // values to the public configuration boundary.
  const loaded = await loadIdentityVerifierConfig(
    raw as LoadIdentityVerifierConfigInput,
  );
  if (!loaded.ok) throw new Error(`invalid test config: ${loaded.reason}`);
  return verifyIdentityJwt(token, loaded.config);
}

describe("verifyIdentityJwt happy path and output", () => {
  it("accepts a minimal RS256 token and returns the canonical identity shape", async () => {
    const result = await verify(await mint());
    expect(result).toEqual({
      subject: "cail-0123456789abcdef0123456789abcdef",
      email: undefined,
      name: undefined,
      entitlements: [],
    });
  });

  it("maps optional identity claims and drops unknown claims", async () => {
    const token = await mint(
      claims({
        email: "user@gc.cuny.edu",
        name: "Ada Lovelace",
        entitlements: ["a", 1, "b"],
        role: "ignored",
      }),
    );
    expect(await verify(token)).toEqual({
      subject: "cail-0123456789abcdef0123456789abcdef",
      email: "user@gc.cuny.edu",
      name: "Ada Lovelace",
      entitlements: ["a", "b"],
    });
  });
});

describe("verifyIdentityJwt structure, encoding, and JSON", () => {
  it.each(["", "a.b", "a.b.c.d", "a.*.c"])("rejects malformed compact JWT %j", async (token) => {
    expect(await verify(token)).toBeNull();
  });

  it("rejects non-object header and payload JSON", async () => {
    const valid = await mint();
    const [, payload, signature] = valid.split(".");
    expect(await verify(`${encodeJson([])}.${payload}.${signature}`)).toBeNull();
    const raw = await signRawRsaPayload(new TextEncoder().encode("[]"), oldKey);
    expect(await verify(raw, oldKey.jwks)).toBeNull();
  });

  it("rejects invalid UTF-8 in header or payload", async () => {
    const valid = await mint();
    const [, payload, signature] = valid.split(".");
    expect(await verify(`${base64url.encode(Uint8Array.of(0xff))}.${payload}.${signature}`)).toBeNull();
    const raw = await signRawRsaPayload(Uint8Array.of(0x7b, 0x22, 0xff, 0x22, 0x7d), oldKey);
    expect(await verify(raw, oldKey.jwks)).toBeNull();
  });

  it("rejects a non-canonical base64url spelling of every segment", async () => {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const withPaddingBits = <Value>(makeValue: (pad: string) => Value): string => {
      for (let length = 0; length < 4; length += 1) {
        const segment = encodeJson(makeValue("a".repeat(length)));
        if ([2, 3].includes(segment.length % 4)) return segment;
      }
      throw new Error("fixture could not produce base64url padding bits");
    };
    const valid = await mint();
    const partsWithPadding = [
      withPaddingBits((pad) => ({ alg: "RS256", kid: testIssuer.kid, pad })),
      withPaddingBits((pad) => ({ ...claims(), pad })),
      valid.split(".")[2]!,
    ];
    for (let index = 0; index < 3; index += 1) {
      const parts = [...partsWithPadding];
      const segment = parts[index]!;
      const remainder = segment.length % 4;
      expect([2, 3]).toContain(remainder);
      const last = alphabet.indexOf(segment.at(-1)!);
      parts[index] = segment.slice(0, -1) + alphabet[last ^ 1];
      expect(base64url.decode(parts[index]!)).toEqual(base64url.decode(segment));
      expect(await verify(parts.join("."))).toBeNull();
    }
  });
});

describe("verifyIdentityJwt algorithm and key selection", () => {
  it.each([undefined, "", 7])("rejects missing or invalid kid %j", async (kid) => {
    const token = await mintRsaJwt(claims(), oldKey, { kid });
    expect(await verify(token, oldKey.jwks)).toBeNull();
  });

  it("rejects an unknown kid", async () => {
    const token = await mintRsaJwt(claims(), oldKey, { kid: "unknown" });
    expect(await verify(token, oldKey.jwks)).toBeNull();
  });

  it("rejects alg confusion even when an HS256 signature is valid", async () => {
    const secret = new TextEncoder().encode(oldKey.publicJwk.n!);
    const token = await new SignJWT(claims())
      .setProtectedHeader({ alg: "HS256", kid: oldKey.kid })
      .sign(secret);
    expect(await verify(token, oldKey.jwks)).toBeNull();
  });

  it("rejects non-RS256 algorithms and any crit member", async () => {
    const valid = await mint();
    const [, payload, signature] = valid.split(".");
    for (const header of [
      { alg: "none", kid: testIssuer.kid },
      { alg: "PS256", kid: testIssuer.kid },
      { alg: "RS256", kid: testIssuer.kid, crit: [] },
    ]) {
      expect(await verify(`${encodeJson(header)}.${payload}.${signature}`)).toBeNull();
    }
  });

  it.each([false, "false", 0, null])(
    "rejects malformed or unencoded-payload b64 header %j",
    async (b64) => {
      const token = await mintRsaJwt(claims(), oldKey, { b64 });
      expect(await verify(token, oldKey.jwks)).toBeNull();
    },
  );

  it("rejects a valid token signed by a different key under the selected kid", async () => {
    const token = await mintRsaJwt(claims(), newKey, { kid: oldKey.kid });
    expect(await verify(token, oldKey.jwks)).toBeNull();
  });
});

describe("verifyIdentityJwt audience, issuer, and subject", () => {
  it.each([
    { aud: undefined },
    { aud: "" },
    { aud: "other" },
    { aud: [] },
    { aud: ["other"] },
    { aud: [AUD, AUD] },
    { aud: [AUD, ""] },
    { aud: [AUD, 7] },
  ])("rejects malformed or unauthorized audience $aud", async ({ aud }) => {
    const value = claims({ aud });
    if (aud === undefined) delete value.aud;
    expect(await verify(await mint(value))).toBeNull();
  });

  it.each([
    { aud: [AUD] },
    { aud: ["service-a", AUD, "service-b"] },
  ])(
    "rejects array audience $aud even when it contains the service audience",
    async ({ aud }) => {
      expect(await verify(await mint(claims({ aud })))).toBeNull();
    },
  );

  it.each([undefined, "", OTHER_ISS, 7])("rejects issuer %j", async (iss) => {
    const value = claims({ iss });
    if (iss === undefined) delete value.iss;
    expect(await verify(await mint(value))).toBeNull();
  });

  it.each([
    `${ISS}/`,
    `${ISS}.evil.example`,
    `https://evil.example/${ISS}`,
    ISS.toUpperCase(),
  ])("rejects issuer near-miss %j", async (iss) => {
    expect(await verify(await mint(claims({ iss })))).toBeNull();
  });

  it("snapshots one exact issuer from an explicitly supplied authority", async () => {
    const opts = { ...OPTS, allowedIssuers: [ISS, OTHER_ISS] };
    expect(
      await verify(await mint(), testIssuer.jwks, opts),
    ).not.toBeNull();
  });

  it.each([
    undefined,
    "",
    7,
    "cail-subject",
    "cail-0123456789ABCDEF0123456789ABCDEF",
    "cail-0123456789abcdef0123456789abcde",
    " cail-0123456789abcdef0123456789abcdef",
  ])("rejects subject %j", async (sub) => {
    const value = claims({ sub });
    if (sub === undefined) delete value.sub;
    expect(await verify(await mint(value))).toBeNull();
  });
});

describe("verifyIdentityJwt time and options", () => {
  it("enforces exp and nbf with the default 60-second tolerance", async () => {
    expect(await verify(await mint(claims({ exp: NOW - 60 })))).toBeNull();
    expect(await verify(await mint(claims({ exp: NOW - 59 })))).not.toBeNull();
    expect(await verify(await mint(claims({ nbf: NOW + 60 })))).not.toBeNull();
    expect(await verify(await mint(claims({ nbf: NOW + 61 })))).toBeNull();
  });

  it("supports strict zero tolerance", async () => {
    const strict = { ...OPTS, clockToleranceSeconds: 0 };
    expect(await verify(await mint(claims({ exp: NOW })), testIssuer.jwks, strict)).toBeNull();
    expect(await verify(await mint(claims({ nbf: NOW })), testIssuer.jwks, strict)).not.toBeNull();
  });

  it.each([undefined, "9999999", Number.NaN, Number.POSITIVE_INFINITY])(
    "rejects invalid exp %j",
    async (exp) => {
      const value = claims({ exp });
      if (exp === undefined) delete value.exp;
      expect(await verify(await mint(value))).toBeNull();
    },
  );

  it.each(["0", Number.NaN, Number.NEGATIVE_INFINITY])("rejects invalid nbf %j", async (nbf) => {
    expect(await verify(await mint(claims({ nbf })))).toBeNull();
  });

  it.each(["0", null, {}, true])("rejects invalid iat %j when present", async (iat) => {
    expect(await verify(await mint(claims({ iat })))).toBeNull();
  });
});

describe("verifyIdentityJwt own-property and fail-closed behavior", () => {
  it("returns null rather than throwing for a wrong token runtime type", async () => {
    // SAFETY: this deliberately injects a wrong runtime token type to verify
    // the public fail-closed boundary.
    await expect(verify(null as never)).resolves.toBeNull();
  });

  it("does not mutate the token, JWKS, options, or claims", async () => {
    const sourceClaims = claims({ entitlements: ["a"] });
    const token = await mint(sourceClaims);
    const jwks = structuredClone(testIssuer.jwks);
    const opts = structuredClone(OPTS);
    const before = JSON.stringify({ sourceClaims, token, jwks, opts });
    await verify(token, jwks, opts);
    expect(JSON.stringify({ sourceClaims, token, jwks, opts })).toBe(before);
  });
});
