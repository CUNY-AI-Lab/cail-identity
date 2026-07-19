import { beforeAll, describe, expect, it } from "vitest";
import { SignJWT, base64url, type JSONWebKeySet } from "jose";
import { verifyIdentityJwt } from "../src/index.js";
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
  return verifyIdentityJwt(
    token,
    jwks as JSONWebKeySet,
    opts as typeof OPTS,
  );
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
    const token = await mintRsaJwt(claims(), oldKey);
    expect(await verify(token, { keys: [oldKey.publicJwk, duplicate] })).toBeNull();
  });

  it("rejects wrong, private, malformed, or non-verification matching JWKs", async () => {
    const token = await mintRsaJwt(claims(), oldKey);
    const invalidKeys = [
      { ...oldKey.publicJwk, kty: "EC" },
      { ...oldKey.publicJwk, alg: "RS512" },
      { ...oldKey.publicJwk, use: "enc" },
      { ...oldKey.publicJwk, key_ops: ["sign"] },
      { ...oldKey.publicJwk, n: "" },
      { ...oldKey.publicJwk, e: "AB" },
      { ...oldKey.publicJwk, d: "private-material" },
    ];
    for (const key of invalidKeys) {
      expect(await verify(token, { keys: [key] })).toBeNull();
    }
  });

  it("rejects malformed JWKS containers and inherited keys", async () => {
    const token = await mintRsaJwt(claims(), oldKey);
    for (const jwks of [null, {}, { keys: null }, { keys: [null] }]) {
      expect(await verify(token, jwks)).toBeNull();
    }
    const inherited = Object.create({ keys: [oldKey.publicJwk] });
    expect(await verify(token, inherited)).toBeNull();
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

  it("rejects multiple configured issuers even when the token matches one", async () => {
    const opts = { ...OPTS, allowedIssuers: [ISS, OTHER_ISS] };
    expect(
      await verify(await mintRsaJwt(claims(), oldKey), oldKey.jwks, opts),
    ).toBeNull();
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

  it.each([
    {},
    { ...OPTS, expectedAudience: "" },
    { ...OPTS, allowedIssuers: [] },
    { ...OPTS, allowedIssuers: [ISS, ISS] },
    { ...OPTS, allowedIssuers: [ISS, ""] },
    { ...OPTS, now: Number.NaN },
    { ...OPTS, now: Number.POSITIVE_INFINITY },
    { ...OPTS, clockToleranceSeconds: -1 },
    { ...OPTS, clockToleranceSeconds: Number.NaN },
  ])("fails closed for invalid options %#", async (opts) => {
    expect(await verify(await mintRsaJwt(claims(), oldKey), oldKey.jwks, opts)).toBeNull();
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
});

describe("verifyIdentityJwt own-property and fail-closed behavior", () => {
  it("does not source required claims or key metadata from prototypes", async () => {
    const token = await mintRsaJwt(claims(), oldKey);
    const inheritedKid = Object.create(oldKey.publicJwk) as Record<string, unknown>;
    delete inheritedKid.kid;
    expect(await verify(token, { keys: [inheritedKid] })).toBeNull();
  });

  it("returns null rather than throwing for wrong runtime input types", async () => {
    await expect(verify(null as unknown as string)).resolves.toBeNull();
    await expect(verify("a.b.c", oldKey.jwks, null)).resolves.toBeNull();
  });

  it("returns null for hostile getters, proxies, and poisoned array methods", async () => {
    const token = await mintRsaJwt(claims(), oldKey);
    const throwing = () => {
      throw new Error("hostile input");
    };
    const hostileJwks = Object.defineProperty({}, "keys", { get: throwing });
    const hostileOpts = new Proxy(OPTS, { getOwnPropertyDescriptor: throwing });
    const poisonedIssuers = [ISS];
    (poisonedIssuers as unknown as Record<string, unknown>).every =
      "not a function";

    await expect(verify(token, hostileJwks)).resolves.toBeNull();
    await expect(verify(token, oldKey.jwks, hostileOpts)).resolves.toBeNull();
    await expect(
      verify(token, oldKey.jwks, { ...OPTS, allowedIssuers: poisonedIssuers }),
    ).resolves.toBeNull();
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
