import { beforeAll, describe, expect, it } from "vitest";

import {
  CAIL_CANONICAL_ISSUER,
  CAIL_STAGING_ISSUER,
  loadIdentityVerifierConfig,
  verifyIdentityJwt,
  type IdentityVerifierConfig,
  type LoadIdentityVerifierConfigInput,
} from "../src/index.js";
import { makeRsaFixture, mintRsaJwt, type RsaFixture } from "./fixtures.js";

const NOW = 1_000_000;
const ISS = CAIL_CANONICAL_ISSUER;
const OTHER_ISS = CAIL_STAGING_ISSUER;
const AUD = "cail-internal";

let key: RsaFixture;
let otherKey: RsaFixture;

beforeAll(async () => {
  [key, otherKey] = await Promise.all([
    makeRsaFixture("config-2026-07"),
    makeRsaFixture("config-2026-08"),
  ]);
});

function input(
  over: Partial<LoadIdentityVerifierConfigInput> = {},
): LoadIdentityVerifierConfigInput {
  return {
    jwks: JSON.stringify(key.jwks),
    issuer: ISS,
    expectedAudience: AUD,
    now: NOW,
    ...over,
  };
}

async function load(
  over: Partial<LoadIdentityVerifierConfigInput> = {},
) {
  return loadIdentityVerifierConfig(input(over));
}

async function mustLoad(
  over: Partial<LoadIdentityVerifierConfigInput> = {},
): Promise<IdentityVerifierConfig> {
  const result = await load(over);
  if (!result.ok) throw new Error(`fixture config failed: ${result.reason}`);
  return result.config;
}

describe("loadIdentityVerifierConfig happy path", () => {
  it("returns a frozen full verifier snapshot", async () => {
    const result = await load();
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config).toMatchObject({
      expectedAudience: AUD,
      issuer: ISS,
      clockToleranceSeconds: 60,
      keyIds: [key.kid],
    });
    expect(Object.isFrozen(result.config)).toBe(true);
    expect(Object.isFrozen(result.config.keyIds)).toBe(true);
  });

  it("accepts both keys during a distinct-kid rotation overlap", async () => {
    const config = await mustLoad({
      jwks: JSON.stringify({
        keys: [key.publicJwk, otherKey.publicJwk],
      }),
    });
    expect(config.keyIds).toEqual([key.kid, otherKey.kid]);

    for (const fixture of [key, otherKey]) {
      const token = await mintRsaJwt(
        {
          sub: "cail-0123456789abcdef0123456789abcdef",
          aud: AUD,
          iss: ISS,
          exp: NOW + 3600,
        },
        fixture,
      );
      await expect(verifyIdentityJwt(token, config)).resolves.not.toBeNull();
    }
  });

  it("loads staging only when it belongs to the configured authority", async () => {
    const result = await load({
      issuer: OTHER_ISS,
      supportedIssuers: [ISS, OTHER_ISS],
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.config.issuer).toBe(OTHER_ISS);
  });
});

describe("loadIdentityVerifierConfig JWKS errors", () => {
  it.each([undefined, "", "   ", "\n\t", 42])(
    "flags unset, blank, or non-string JWKS (%j)",
    async (jwks) => {
      await expect(
        load({ jwks: jwks as string | undefined }),
      ).resolves.toEqual({ ok: false, reason: "jwks_missing" });
    },
  );

  it.each([
    ["truncated JSON", '{"keys": ['],
    ["non-JSON text", "not json at all"],
    ["JSON null", "null"],
    ["JSON string", '"keys"'],
    ["JSON array", "[]"],
    ["object without keys", "{}"],
    ["keys not an array", '{"keys": {}}'],
    ["empty keys", '{"keys": []}'],
    ["empty key", '{"keys": [{}]}'],
    ["non-object key", '{"keys": [null]}'],
  ])("flags %s", async (_name, jwks) => {
    await expect(load({ jwks })).resolves.toEqual({
      ok: false,
      reason: "jwks_malformed",
    });
  });

  it("requires a nonempty distinct kid on every eligible public RS256 key", async () => {
    for (const jwks of [
      { keys: [{ ...key.publicJwk, kid: undefined }] },
      { keys: [{ ...key.publicJwk, kid: "" }] },
      { keys: [key.publicJwk, { ...key.publicJwk }] },
    ]) {
      await expect(load({ jwks: JSON.stringify(jwks) })).resolves.toEqual({
        ok: false,
        reason: "jwks_malformed",
      });
    }
  });

  it("rejects every structurally ineligible or private JWK", async () => {
    const invalidKeys = [
      { ...key.publicJwk, kty: "EC" },
      { ...key.publicJwk, alg: "RS512" },
      { ...key.publicJwk, use: "enc" },
      { ...key.publicJwk, key_ops: ["sign"] },
      { ...key.publicJwk, key_ops: ["verify", "verify"] },
      { ...key.publicJwk, n: "" },
      { ...key.publicJwk, e: "AB" },
      { ...key.publicJwk, d: "private-material" },
      { ...key.publicJwk, k: "c2VjcmV0LWtleQ" },
      { ...key.publicJwk, oth: [] },
    ];
    for (const invalidKey of invalidKeys) {
      await expect(
        load({ jwks: JSON.stringify({ keys: [invalidKey] }) }),
      ).resolves.toEqual({ ok: false, reason: "jwks_malformed" });
    }
  });

  it("requires canonical minimal Base64urlUInt n and e", async () => {
    const withLeadingZero = (value: string): string => {
      const bytes = Buffer.from(value.replaceAll("-", "+").replaceAll("_", "/"), "base64");
      return Buffer.from([0, ...bytes])
        .toString("base64url");
    };
    for (const invalidKey of [
      { ...key.publicJwk, n: withLeadingZero(key.publicJwk.n!) },
      { ...key.publicJwk, e: withLeadingZero(key.publicJwk.e!) },
    ]) {
      await expect(
        load({ jwks: JSON.stringify({ keys: [invalidKey] }) }),
      ).resolves.toEqual({ ok: false, reason: "jwks_malformed" });
    }
  });

  it("accepts a valid 2048-bit RS256 public key", async () => {
    const modulus = Buffer.from(key.publicJwk.n!, "base64url");
    expect(modulus).toHaveLength(256);
    expect(modulus[0]! & 0x80).not.toBe(0);
    expect(key.publicJwk.e).toBe("AQAB");
    await expect(load()).resolves.toMatchObject({ ok: true });
    await expect(
      load({
        jwks: JSON.stringify({
          keys: [{ ...key.publicJwk, e: "Aw" }],
        }),
      }),
    ).resolves.toMatchObject({ ok: true });
  });

  it("rejects unusable RSA public numbers before import", async () => {
    const evenModulus = Buffer.from(key.publicJwk.n!, "base64url");
    evenModulus[evenModulus.length - 1] =
      evenModulus[evenModulus.length - 1]! & 0xfe;
    const shortModulus = Buffer.from(key.publicJwk.n!, "base64url");
    shortModulus[0] = 0x7f;
    const tooLargeSafeExponent = Buffer.from([
      0x20, 0, 0, 0, 0, 0, 1,
    ]).toString("base64url");

    const invalidKeys = [
      { ...key.publicJwk, e: "AQ" }, // 1
      { ...key.publicJwk, e: "Ag" }, // 2
      { ...key.publicJwk, e: tooLargeSafeExponent },
      { ...key.publicJwk, n: "AQ", e: "AQAB" }, // tiny odd modulus
      { ...key.publicJwk, n: "Ag", e: "Aw" }, // tiny even modulus
      { ...key.publicJwk, n: "AA" }, // zero modulus
      {
        ...key.publicJwk,
        n: Buffer.from("arbitrary modulus bytes").toString("base64url"),
      },
      { ...key.publicJwk, n: evenModulus.toString("base64url") },
      { ...key.publicJwk, n: shortModulus.toString("base64url") },
    ];

    for (const invalidKey of invalidKeys) {
      await expect(
        load({ jwks: JSON.stringify({ keys: [invalidKey] }) }),
      ).resolves.toEqual({ ok: false, reason: "jwks_malformed" });
    }
  });

  it("rejects malformed RSA public-number encodings", async () => {
    const withLeadingZero = (value: string): string =>
      Buffer.from([0, ...Buffer.from(value, "base64url")]).toString(
        "base64url",
      );
    const invalidKeys = [
      { ...key.publicJwk, n: `${key.publicJwk.n!}=` },
      { ...key.publicJwk, e: `${key.publicJwk.e!}=` },
      { ...key.publicJwk, n: `+${key.publicJwk.n!.slice(1)}` },
      { ...key.publicJwk, e: "AB" },
      { ...key.publicJwk, n: withLeadingZero(key.publicJwk.n!) },
      { ...key.publicJwk, e: withLeadingZero(key.publicJwk.e!) },
    ];

    for (const invalidKey of invalidKeys) {
      await expect(
        load({ jwks: JSON.stringify({ keys: [invalidKey] }) }),
      ).resolves.toEqual({ ok: false, reason: "jwks_malformed" });
    }
  });

  it("uses parsed own-data JSON and never honors inherited key metadata", async () => {
    const inherited = Object.create(key.publicJwk) as Record<string, unknown>;
    inherited.kid = key.kid;
    await expect(
      load({ jwks: JSON.stringify({ keys: [inherited] }) }),
    ).resolves.toEqual({ ok: false, reason: "jwks_malformed" });

    const json = JSON.stringify({
      keys: [{ ...key.publicJwk, __proto__: { d: "private" } }],
    });
    const result = await load({ jwks: json });
    expect(result.ok).toBe(true);
    expect(({} as { d?: string }).d).toBeUndefined();
  });
});

describe("loadIdentityVerifierConfig issuer authority", () => {
  it.each([undefined, "", 7])("flags missing issuer %j", async (issuer) => {
    await expect(
      load({ issuer: issuer as string | undefined }),
    ).resolves.toEqual({ ok: false, reason: "issuer_missing" });
  });

  it.each([
    ` ${ISS}`,
    `${ISS} `,
    `${ISS}\u0000`,
    `${ISS}?query=1`,
    `${ISS}#fragment`,
    "http://tools.ailab.gc.cuny.edu/cail-sso",
    "https://TOOLS.AILAB.GC.CUNY.EDU/cail-sso",
    "https://user@tools.ailab.gc.cuny.edu/cail-sso",
  ])("rejects noncanonical issuer %j", async (issuer) => {
    await expect(load({ issuer })).resolves.toEqual({
      ok: false,
      reason: "issuer_unsupported",
    });
  });

  it("rejects an issuer outside the default or supplied authority", async () => {
    const outside = "https://evil.example/cail-sso";
    await expect(load({ issuer: outside })).resolves.toEqual({
      ok: false,
      reason: "issuer_unsupported",
    });
    await expect(
      load({ issuer: outside, supportedIssuers: [ISS, OTHER_ISS] }),
    ).resolves.toEqual({ ok: false, reason: "issuer_unsupported" });
  });

  it.each([
    [[]],
    [[ISS, ISS]],
    [[ISS, ""]],
    [[ISS, 7]],
    [[`${ISS}/`]],
  ])("rejects malformed supported issuer authority %#", async (values) => {
    await expect(
      load({ supportedIssuers: values as unknown as string[] }),
    ).resolves.toEqual({ ok: false, reason: "issuer_unsupported" });
  });
});

describe("loadIdentityVerifierConfig audience and timing", () => {
  it.each([undefined, ""])("flags missing audience %j", async (expectedAudience) => {
    await expect(load({ expectedAudience })).resolves.toEqual({
      ok: false,
      reason: "audience_missing",
    });
  });

  it.each([["cail:x"], 7, " ", "   ", "cail:\u0000x"])(
    "rejects nonscalar or malformed audience %j",
    async (expectedAudience) => {
      await expect(
        load({ expectedAudience: expectedAudience as unknown as string }),
      ).resolves.toEqual({ ok: false, reason: "audience_malformed" });
    },
  );

  it.each([" ", "   "])(
    "rejects a matching signed token for whitespace-only audience %j at the config boundary",
    async (expectedAudience) => {
      const matchingToken = await mintRsaJwt(
        {
          sub: "cail-0123456789abcdef0123456789abcdef",
          aud: expectedAudience,
          iss: ISS,
          exp: NOW + 3600,
        },
        key,
      );
      const loaded = await load({ expectedAudience });
      expect(loaded).toEqual({ ok: false, reason: "audience_malformed" });

      const validConfig = await mustLoad();
      await expect(
        verifyIdentityJwt(matchingToken, validConfig),
      ).resolves.toBeNull();
    },
  );

  it.each([
    { now: Number.NaN },
    { now: Number.POSITIVE_INFINITY },
    { now: 8_640_000_000_001 },
    { clockToleranceSeconds: -1 },
    { clockToleranceSeconds: Number.NaN },
    { clockToleranceSeconds: Number.POSITIVE_INFINITY },
    { clockToleranceSeconds: 301 },
  ])("rejects invalid bounded timing %#", async (timing) => {
    await expect(load(timing)).resolves.toEqual({
      ok: false,
      reason: "timing_invalid",
    });
  });

  it("accepts strict zero tolerance and the maximum finite Date bound", async () => {
    const result = await load({
      now: 8_640_000_000_000,
      clockToleranceSeconds: 0,
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.config.clockToleranceSeconds).toBe(0);
  });
});

describe("immutable snapshots and hostile accessors", () => {
  it("reads every top-level option exactly once and uses those exact values", async () => {
    const counts = new Map<string, number>();
    const valid: Record<string, unknown> = {
      jwks: JSON.stringify(key.jwks),
      issuer: ISS,
      expectedAudience: AUD,
      supportedIssuers: [ISS],
      now: NOW,
      clockToleranceSeconds: 0,
    };
    const later: Record<string, unknown> = {
      jwks: '{"keys":[]}',
      issuer: "https://evil.example/",
      expectedAudience: ["wrong"],
      supportedIssuers: [],
      now: Number.NaN,
      clockToleranceSeconds: 301,
    };
    const hostile = Object.create(null) as Record<string, unknown>;
    for (const name of Object.keys(valid)) {
      Object.defineProperty(hostile, name, {
        enumerable: true,
        get() {
          const count = (counts.get(name) ?? 0) + 1;
          counts.set(name, count);
          return count === 1 ? valid[name] : later[name];
        },
      });
    }

    const result = await loadIdentityVerifierConfig(
      hostile as unknown as LoadIdentityVerifierConfigInput,
    );
    expect(result.ok).toBe(true);
    expect(Object.fromEntries(counts)).toEqual({
      jwks: 1,
      issuer: 1,
      expectedAudience: 1,
      supportedIssuers: 1,
      now: 1,
      clockToleranceSeconds: 1,
    });
  });

  it("snapshots each supported-issuer element once", async () => {
    let reads = 0;
    const issuers = [ISS];
    Object.defineProperty(issuers, 0, {
      configurable: true,
      enumerable: true,
      get() {
        reads += 1;
        return reads === 1 ? ISS : "https://evil.example/";
      },
    });
    const result = await load({ supportedIssuers: issuers });
    expect(result.ok).toBe(true);
    expect(reads).toBe(1);
  });

  it("returns an owned config error instead of throwing on hostile proxies", async () => {
    const throwing = () => {
      throw new Error("hostile config input");
    };
    const hostileInput = new Proxy({}, { getOwnPropertyDescriptor: throwing });
    await expect(
      loadIdentityVerifierConfig(hostileInput as never),
    ).resolves.toEqual({ ok: false, reason: "jwks_missing" });

    const hostileAllowlist = new Proxy([ISS], { get: throwing });
    await expect(
      load({ supportedIssuers: hostileAllowlist }),
    ).resolves.toEqual({ ok: false, reason: "issuer_unsupported" });
  });

  it("rejects forged verifier objects as configuration misuse, not token failure", async () => {
    await expect(
      verifyIdentityJwt(
        "a.b.c",
        {
          expectedAudience: AUD,
          issuer: ISS,
          clockToleranceSeconds: 60,
          keyIds: [key.kid],
        } as unknown as IdentityVerifierConfig,
      ),
    ).rejects.toThrow("snapshot returned by loadIdentityVerifierConfig");
  });
});
