import { beforeAll, describe, expect, it } from "vitest";
import { SignJWT, base64url } from "jose";
import {
  loadIdentityVerifierConfig,
  verifyIdentityJwt,
  type LoadIdentityVerifierConfigInput,
} from "../src/index.js";
import {
  encodeJson,
  makeRsaFixture,
  mintRsaJwt,
  signRawRsaPayload,
  type RsaFixture,
} from "./fixtures.js";

const NOW = 1_000_000;
const ISS = "https://tools.ailab.gc.cuny.edu/cail-sso";
const OTHER_ISS = "https://tools.cuny.qzz.io/cail-sso";
const AUD = "cail-internal";
const OPTS = { expectedAudience: AUD, allowedIssuers: [ISS], now: NOW };

let oldKey: RsaFixture;
let newKey: RsaFixture;

beforeAll(async () => {
  [oldKey, newKey] = await Promise.all([
    makeRsaFixture("old-2026-07"),
    makeRsaFixture("new-2026-08"),
  ]);
});

function claims(over: Record<string, unknown> = {}) {
  return {
    sub: "cail-0123456789abcdef0123456789abcdef",
    aud: AUD,
    iss: ISS,
    exp: NOW + 3600,
    ...over,
  };
}

async function verify(
  token: string,
  jwks: unknown = oldKey.jwks,
  opts: unknown = OPTS,
) {
  const values = opts as Partial<typeof OPTS> & {
    allowedIssuers?: unknown;
    expectedAudience?: unknown;
    now?: unknown;
    clockToleranceSeconds?: unknown;
  };
  const allowedIssuers = values.allowedIssuers;
  const issuer =
    Array.isArray(allowedIssuers) && typeof allowedIssuers[0] === "string"
      ? allowedIssuers[0]
      : undefined;
  const loaded = await loadIdentityVerifierConfig({
    jwks: JSON.stringify(jwks),
    issuer,
    expectedAudience: values.expectedAudience,
    supportedIssuers: allowedIssuers,
    now: values.now,
    clockToleranceSeconds: values.clockToleranceSeconds,
  } as LoadIdentityVerifierConfigInput);
  if (!loaded.ok) throw new Error(`invalid test config: ${loaded.reason}`);
  return verifyIdentityJwt(token, loaded.config);
}

async function expectConfigError(
  jwks: unknown,
  reason = "jwks_malformed",
) {
  const result = await loadIdentityVerifierConfig({
    jwks: JSON.stringify(jwks),
    issuer: ISS,
    expectedAudience: AUD,
    now: NOW,
  });
  expect(result).toEqual({ ok: false, reason });
}

describe("verifyIdentityJwt happy path and output", () => {
  it("accepts a minimal RS256 token and returns the canonical identity shape", async () => {
    const result = await verify(await mintRsaJwt(claims(), oldKey));
    expect(result).toEqual({
      subject: "cail-0123456789abcdef0123456789abcdef",
      email: undefined,
      name: undefined,
      entitlements: [],
    });
  });

  it("maps optional identity claims and drops unknown claims", async () => {
    const token = await mintRsaJwt(
      claims({
        email: "user@gc.cuny.edu",
        name: "Ada Lovelace",
        entitlements: ["a", 1, "b"],
        role: "ignored",
      }),
      oldKey,
    );
    expect(await verify(token)).toEqual({
      subject: "cail-0123456789abcdef0123456789abcdef",
      email: "user@gc.cuny.edu",
      name: "Ada Lovelace",
      entitlements: ["a", "b"],
    });
  });

  it("accepts the exact scalar service audience", async () => {
    expect(await verify(await mintRsaJwt(claims(), oldKey))).not.toBeNull();
  });

  it("accepts either key during a distinct-kid rotation overlap", async () => {
    const jwks = { keys: [oldKey.publicJwk, newKey.publicJwk] };
    expect(await verify(await mintRsaJwt(claims(), oldKey), jwks)).not.toBeNull();
    expect(await verify(await mintRsaJwt(claims(), newKey), jwks)).not.toBeNull();
  });
});

describe("verifyIdentityJwt structure, encoding, and JSON", () => {
  it.each(["", "a.b", "a.b.c.d", "a.*.c"])("rejects malformed compact JWT %j", async (token) => {
    expect(await verify(token)).toBeNull();
  });

  it("rejects non-object header and payload JSON", async () => {
    const valid = await mintRsaJwt(claims(), oldKey);
    const [, payload, signature] = valid.split(".");
    expect(await verify(`${encodeJson([])}.${payload}.${signature}`)).toBeNull();
    const raw = await signRawRsaPayload(new TextEncoder().encode("[]"), oldKey);
    expect(await verify(raw)).toBeNull();
  });

  it("rejects invalid UTF-8 in header or payload", async () => {
    const valid = await mintRsaJwt(claims(), oldKey);
    const [, payload, signature] = valid.split(".");
    expect(await verify(`${base64url.encode(Uint8Array.of(0xff))}.${payload}.${signature}`)).toBeNull();
    const raw = await signRawRsaPayload(Uint8Array.of(0x7b, 0x22, 0xff, 0x22, 0x7d), oldKey);
    expect(await verify(raw)).toBeNull();
  });

  it("rejects a non-canonical base64url spelling of every segment", async () => {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const withPaddingBits = (makeValue: (pad: string) => unknown): string => {
      for (let length = 0; length < 4; length += 1) {
        const segment = encodeJson(makeValue("a".repeat(length)));
        if ([2, 3].includes(segment.length % 4)) return segment;
      }
      throw new Error("fixture could not produce base64url padding bits");
    };
    const valid = await mintRsaJwt(claims(), oldKey);
    const partsWithPadding = [
      withPaddingBits((pad) => ({ alg: "RS256", kid: oldKey.kid, pad })),
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
    expect(await verify(token)).toBeNull();
  });

  it("rejects an unknown kid", async () => {
    const token = await mintRsaJwt(claims(), oldKey, { kid: "unknown" });
    expect(await verify(token)).toBeNull();
  });

  it("rejects duplicate eligible RSA signing keys for one kid", async () => {
    const duplicate = { ...oldKey.publicJwk };
    await expectConfigError({ keys: [oldKey.publicJwk, duplicate] });
  });

  it("owns wrong, private, malformed, or non-verification JWKs as config errors", async () => {
    const invalidKeys = [
      { ...oldKey.publicJwk, kty: "EC" },
      { ...oldKey.publicJwk, alg: "RS512" },
      { ...oldKey.publicJwk, use: "enc" },
      { ...oldKey.publicJwk, key_ops: ["sign"] },
      { ...oldKey.publicJwk, n: "" },
      { ...oldKey.publicJwk, e: "AB" },
      { ...oldKey.publicJwk, d: "private-material" },
      { ...oldKey.publicJwk, k: "c2VjcmV0LWtleQ" },
      { ...oldKey.publicJwk, oth: [] },
    ];
    for (const key of invalidKeys) {
      await expectConfigError({ keys: [key] });
    }
  });

  it("owns non-minimal Base64urlUInt encodings as config errors", async () => {
    const withLeadingZero = (value: string): string =>
      base64url.encode(Uint8Array.from([0, ...base64url.decode(value)]));

    for (const key of [
      { ...oldKey.publicJwk, n: withLeadingZero(oldKey.publicJwk.n!) },
      { ...oldKey.publicJwk, e: withLeadingZero(oldKey.publicJwk.e!) },
    ]) {
      await expectConfigError({ keys: [key] });
    }
  });

  it("owns private material anywhere in the supplied JWKS as config error", async () => {
    const unrelatedSecret = {
      kty: "oct",
      kid: "must-not-be-in-a-public-jwks",
      k: "c2VjcmV0LWtleQ",
    };
    await expectConfigError({
      keys: [oldKey.publicJwk, unrelatedSecret],
    });
  });

  it("owns malformed JWKS containers and inherited keys as config errors", async () => {
    for (const jwks of [null, {}, { keys: null }, { keys: [null] }]) {
      await expectConfigError(jwks);
    }
    const inherited = Object.create({ keys: [oldKey.publicJwk] });
    await expectConfigError(inherited);
  });

  it("rejects alg confusion even when an HS256 signature is valid", async () => {
    const secret = new TextEncoder().encode(oldKey.publicJwk.n!);
    const token = await new SignJWT(claims())
      .setProtectedHeader({ alg: "HS256", kid: oldKey.kid })
      .sign(secret);
    expect(await verify(token)).toBeNull();
  });

  it("rejects non-RS256 algorithms and any crit member", async () => {
    const valid = await mintRsaJwt(claims(), oldKey);
    const [, payload, signature] = valid.split(".");
    for (const header of [
      { alg: "none", kid: oldKey.kid },
      { alg: "PS256", kid: oldKey.kid },
      { alg: "RS256", kid: oldKey.kid, crit: [] },
    ]) {
      expect(await verify(`${encodeJson(header)}.${payload}.${signature}`)).toBeNull();
    }
  });

  it.each([false, "false", 0, null])(
    "rejects malformed or unencoded-payload b64 header %j",
    async (b64) => {
      const token = await mintRsaJwt(claims(), oldKey, { b64 });
      expect(await verify(token)).toBeNull();
    },
  );

  it("rejects a valid token signed by a different key under the selected kid", async () => {
    const token = await mintRsaJwt(claims(), newKey, { kid: oldKey.kid });
    expect(await verify(token)).toBeNull();
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
    const value = claims({ aud }) as Record<string, unknown>;
    if (aud === undefined) delete value.aud;
    expect(await verify(await mintRsaJwt(value, oldKey))).toBeNull();
  });

  it.each([
    { aud: [AUD] },
    { aud: ["service-a", AUD, "service-b"] },
  ])(
    "rejects array audience $aud even when it contains the service audience",
    async ({ aud }) => {
      expect(await verify(await mintRsaJwt(claims({ aud }), oldKey))).toBeNull();
    },
  );

  it.each([undefined, "", OTHER_ISS, 7])("rejects issuer %j", async (iss) => {
    const value = claims({ iss }) as Record<string, unknown>;
    if (iss === undefined) delete value.iss;
    expect(await verify(await mintRsaJwt(value, oldKey))).toBeNull();
  });

  it.each([
    `${ISS}/`,
    `${ISS}.evil.example`,
    `https://evil.example/${ISS}`,
    ISS.toUpperCase(),
  ])("rejects issuer near-miss %j", async (iss) => {
    expect(await verify(await mintRsaJwt(claims({ iss }), oldKey))).toBeNull();
  });

  it("snapshots one exact issuer even when the authority supports prod and staging", async () => {
    const opts = { ...OPTS, allowedIssuers: [ISS, OTHER_ISS] };
    expect(
      await verify(await mintRsaJwt(claims(), oldKey), oldKey.jwks, opts),
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
    const value = claims({ sub }) as Record<string, unknown>;
    if (sub === undefined) delete value.sub;
    expect(await verify(await mintRsaJwt(value, oldKey))).toBeNull();
  });
});

describe("verifyIdentityJwt time and options", () => {
  it("enforces exp and nbf with the default 60-second tolerance", async () => {
    expect(await verify(await mintRsaJwt(claims({ exp: NOW - 60 }), oldKey))).toBeNull();
    expect(await verify(await mintRsaJwt(claims({ exp: NOW - 59 }), oldKey))).not.toBeNull();
    expect(await verify(await mintRsaJwt(claims({ nbf: NOW + 60 }), oldKey))).not.toBeNull();
    expect(await verify(await mintRsaJwt(claims({ nbf: NOW + 61 }), oldKey))).toBeNull();
  });

  it("supports strict zero tolerance", async () => {
    const strict = { ...OPTS, clockToleranceSeconds: 0 };
    expect(await verify(await mintRsaJwt(claims({ exp: NOW }), oldKey), oldKey.jwks, strict)).toBeNull();
    expect(await verify(await mintRsaJwt(claims({ nbf: NOW }), oldKey), oldKey.jwks, strict)).not.toBeNull();
  });

  it.each([undefined, "9999999", Number.NaN, Number.POSITIVE_INFINITY])(
    "rejects invalid exp %j",
    async (exp) => {
      const value = claims({ exp }) as Record<string, unknown>;
      if (exp === undefined) delete value.exp;
      expect(await verify(await mintRsaJwt(value, oldKey))).toBeNull();
    },
  );

  it.each(["0", Number.NaN, Number.NEGATIVE_INFINITY])("rejects invalid nbf %j", async (nbf) => {
    expect(await verify(await mintRsaJwt(claims({ nbf }), oldKey))).toBeNull();
  });

  it.each(["0", null, {}, true])("rejects invalid iat %j when present", async (iat) => {
    expect(await verify(await mintRsaJwt(claims({ iat }), oldKey))).toBeNull();
  });
});

describe("verifyIdentityJwt own-property and fail-closed behavior", () => {
  it("does not source key metadata from prototypes during config loading", async () => {
    const inheritedKid = Object.create(oldKey.publicJwk) as Record<string, unknown>;
    delete inheritedKid.kid;
    await expectConfigError({ keys: [inheritedKid] });
  });

  it("returns null rather than throwing for a wrong token runtime type", async () => {
    await expect(verify(null as unknown as string)).resolves.toBeNull();
  });

  it("does not mutate the token, JWKS, options, or claims", async () => {
    const sourceClaims = claims({ entitlements: ["a"] });
    const token = await mintRsaJwt(sourceClaims, oldKey);
    const jwks = structuredClone(oldKey.jwks);
    const opts = structuredClone(OPTS);
    const before = JSON.stringify({ sourceClaims, token, jwks, opts });
    await verify(token, jwks, opts);
    expect(JSON.stringify({ sourceClaims, token, jwks, opts })).toBe(before);
  });
});
