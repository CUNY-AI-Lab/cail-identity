import { beforeAll, describe, expect, it } from "vitest";
import type { JWK } from "jose";

import {
  CAIL_CANONICAL_ISSUER,
  loadIdentityVerifierConfig,
  verifyIdentityJwt,
  type IdentityVerifierConfig,
  type LoadIdentityVerifierConfigInput,
} from "../src/index.js";
import {
  createTestIdentityIssuer,
  type TestIdentityIssuer,
} from "../src/testing.js";
import {
  type JsonObject,
  type JsonValue,
} from "./fixtures.js";

const NOW = 1_000_000;
const ISS = CAIL_CANONICAL_ISSUER;
const OTHER_ISS = "https://test-issuer.example/cail-sso";
const AUD = "cail-internal";
const MAX_JWKS_JSON_DEPTH = 64;

let key: TestIdentityIssuer;
let keyJwk: JWK;
let otherKey: TestIdentityIssuer;
let otherKeyJwk: JWK;

function onlyPublicJwk(issuer: TestIdentityIssuer): JWK {
  const publicJwk = issuer.jwks.keys[0];
  if (publicJwk === undefined) throw new Error("test issuer has no public key");
  return publicJwk;
}

beforeAll(async () => {
  [key, otherKey] = await Promise.all([
    createTestIdentityIssuer({ kid: "config-2026-07" }),
    createTestIdentityIssuer({ kid: "config-2026-08" }),
  ]);
  keyJwk = onlyPublicJwk(key);
  otherKeyJwk = onlyPublicJwk(otherKey);
});

type ConfigTestOverrides = {
  jwks?: JsonValue;
  issuer?: JsonValue;
  expectedAudience?: JsonValue;
  supportedIssuers?: JsonValue;
  now?: JsonValue;
  clockToleranceSeconds?: JsonValue;
};

function input(over: ConfigTestOverrides = {}): LoadIdentityVerifierConfigInput {
  const raw = {
    jwks: key.jwksJson,
    issuer: ISS,
    expectedAudience: AUD,
    now: NOW,
    ...over,
  };
  // SAFETY: this helper intentionally forwards malformed JSON-shaped values
  // from negative tests into the public configuration boundary.
  return raw as LoadIdentityVerifierConfigInput;
}

async function load(over: ConfigTestOverrides = {}) {
  return loadIdentityVerifierConfig(input(over));
}

async function mustLoad(over: ConfigTestOverrides = {}): Promise<IdentityVerifierConfig> {
  const result = await load(over);
  if (!result.ok) throw new Error(`fixture config failed: ${result.reason}`);
  return result.config;
}

type JwksMetadata = string | JwksMetadata[];

function valueAtJwksDepth(depth: number): JwksMetadata {
  let value: JwksMetadata = "ignored metadata";
  for (let current = 1; current < depth; current += 1) {
    value = [value];
  }
  return value;
}

function jwksWithMetadataAtDepth(depth: number): string {
  return JSON.stringify({
    keys: [keyJwk],
    metadata: valueAtJwksDepth(depth),
  });
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
        keys: [keyJwk, otherKeyJwk],
      }),
    });
    expect(config.keyIds).toEqual([key.kid, otherKey.kid]);

    for (const fixture of [key, otherKey]) {
      const token = await fixture.mintIdentityJwt({
        audience: AUD,
        subject: "cail-0123456789abcdef0123456789abcdef",
        now: NOW,
        claims: {
          sub: "cail-0123456789abcdef0123456789abcdef",
          aud: AUD,
          iss: ISS,
          exp: NOW + 3600,
          iat: undefined,
        },
      });
      await expect(verifyIdentityJwt(token, config)).resolves.not.toBeNull();
    }
  });

  it("loads an additional issuer only when the caller explicitly trusts it", async () => {
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
      await expect(load({ jwks })).resolves.toEqual({
        ok: false,
        reason: "jwks_missing",
      });
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

  it.each([
    [MAX_JWKS_JSON_DEPTH - 1, true],
    [MAX_JWKS_JSON_DEPTH, true],
    [MAX_JWKS_JSON_DEPTH + 1, false],
  ])(
    "enforces the iterative JWKS JSON depth boundary at %i",
    async (depth, accepted) => {
      const result = await load({ jwks: jwksWithMetadataAtDepth(depth) });
      expect(result.ok).toBe(accepted);
    },
  );

  it("rejects very deep unknown metadata without a stack-dependent walk", async () => {
    const depth = 5_000;
    const nested = `${"[".repeat(depth)}0${"]".repeat(depth)}`;
    const jwks = `{"keys":[${JSON.stringify(keyJwk)}],"metadata":${nested}}`;
    await expect(load({ jwks })).resolves.toEqual({
      ok: false,
      reason: "jwks_malformed",
    });
  });

  it("accepts wide ordinary unknown metadata", async () => {
    const metadata = Object.fromEntries(
      Array.from({ length: 1_000 }, (_, index) => [`extension_${index}`, index]),
    );
    await expect(
      load({
        jwks: JSON.stringify({
          keys: [keyJwk],
          metadata,
          "urn:example:extension": { enabled: true },
        }),
      }),
    ).resolves.toMatchObject({ ok: true });
  });

  it("requires a nonempty distinct kid on every eligible public RS256 key", async () => {
    for (const jwks of [
      { keys: [{ ...keyJwk, kid: undefined }] },
      { keys: [{ ...keyJwk, kid: "" }] },
      { keys: [keyJwk, { ...keyJwk }] },
    ]) {
      await expect(load({ jwks: JSON.stringify(jwks) })).resolves.toEqual({
        ok: false,
        reason: "jwks_malformed",
      });
    }
  });

  it("rejects every structurally ineligible or private JWK", async () => {
    const invalidKeys = [
      { ...keyJwk, kty: "EC" },
      { ...keyJwk, alg: "RS512" },
      { ...keyJwk, use: "enc" },
      { ...keyJwk, key_ops: ["sign"] },
      { ...keyJwk, key_ops: ["verify", "verify"] },
      { ...keyJwk, n: "" },
      { ...keyJwk, e: "AB" },
      { ...keyJwk, d: "private-material" },
      { ...keyJwk, k: "c2VjcmV0LWtleQ" },
      { ...keyJwk, oth: [] },
    ];
    for (const invalidKey of invalidKeys) {
      await expect(
        load({ jwks: JSON.stringify({ keys: [invalidKey] }) }),
      ).resolves.toEqual({ ok: false, reason: "jwks_malformed" });
    }

    await expect(
      load({
        jwks: JSON.stringify({
          keys: [
            keyJwk,
            {
              kty: "oct",
              kid: "must-not-be-in-a-public-jwks",
              k: "c2VjcmV0LWtleQ",
            },
          ],
        }),
      }),
    ).resolves.toEqual({ ok: false, reason: "jwks_malformed" });
  });

  it("rejects unusable RSA public numbers before import", async () => {
    const evenModulus = Buffer.from(keyJwk.n!, "base64url");
    evenModulus[evenModulus.length - 1] =
      evenModulus[evenModulus.length - 1]! & 0xfe;
    const shortModulus = Buffer.from(keyJwk.n!, "base64url");
    shortModulus[0] = 0x7f;
    const tooLargeSafeExponent = Buffer.from([
      0x20, 0, 0, 0, 0, 0, 1,
    ]).toString("base64url");

    const invalidKeys = [
      { ...keyJwk, e: "AQ" }, // 1
      { ...keyJwk, e: "Ag" }, // 2
      { ...keyJwk, e: tooLargeSafeExponent },
      { ...keyJwk, n: "AQ", e: "AQAB" }, // tiny odd modulus
      { ...keyJwk, n: "Ag", e: "Aw" }, // tiny even modulus
      { ...keyJwk, n: "AA" }, // zero modulus
      {
        ...keyJwk,
        n: Buffer.from("arbitrary modulus bytes").toString("base64url"),
      },
      { ...keyJwk, n: evenModulus.toString("base64url") },
      { ...keyJwk, n: shortModulus.toString("base64url") },
    ];

    for (const invalidKey of invalidKeys) {
      await expect(
        load({ jwks: JSON.stringify({ keys: [invalidKey] }) }),
      ).resolves.toEqual({ ok: false, reason: "jwks_malformed" });
    }

    await expect(
      load({
        jwks: JSON.stringify({
          keys: [{ ...keyJwk, e: "Aw" }],
        }),
      }),
    ).resolves.toMatchObject({ ok: true });
  });

  it("rejects malformed RSA public-number encodings", async () => {
    const withLeadingZero = (value: string): string =>
      Buffer.from([0, ...Buffer.from(value, "base64url")]).toString(
        "base64url",
      );
    const invalidKeys = [
      { ...keyJwk, n: `${keyJwk.n!}=` },
      { ...keyJwk, e: `${keyJwk.e!}=` },
      { ...keyJwk, n: `+${keyJwk.n!.slice(1)}` },
      { ...keyJwk, e: "AB" },
      { ...keyJwk, n: withLeadingZero(keyJwk.n!) },
      { ...keyJwk, e: withLeadingZero(keyJwk.e!) },
    ];

    for (const invalidKey of invalidKeys) {
      await expect(
        load({ jwks: JSON.stringify({ keys: [invalidKey] }) }),
      ).resolves.toEqual({ ok: false, reason: "jwks_malformed" });
    }
  });

  it("uses parsed own-data JSON and never honors inherited key metadata", async () => {
    // SAFETY: the null-prototype object intentionally inherits key metadata;
    // this test verifies parsed JSON does not honor that prototype.
    const inherited = Object.create(keyJwk) as { kid: string };
    inherited.kid = key.kid;
    await expect(
      load({ jwks: JSON.stringify({ keys: [inherited] }) }),
    ).resolves.toEqual({ ok: false, reason: "jwks_malformed" });

    const json = JSON.stringify({
      keys: [{ ...keyJwk, __proto__: { d: "private" } }],
    });
    const result = await load({ jwks: json });
    expect(result.ok).toBe(true);
    expect({ d: undefined }.d).toBeUndefined();
  });
});

describe("loadIdentityVerifierConfig issuer authority", () => {
  it.each([undefined, "", 7])("flags missing issuer %j", async (issuer) => {
    await expect(
      load({ issuer }),
    ).resolves.toEqual({ ok: false, reason: "issuer_missing" });
  });

  it.each([
    ` ${ISS}`,
    `${ISS} `,
    `${ISS}\u0000`,
    `${ISS}?query=1`,
    `${ISS}#fragment`,
    "http://issuer.example/cail-sso",
    "https://TOOLS.AILAB.GC.CUNY.EDU/cail-sso",
    "https://user@issuer.example/cail-sso",
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
      load({ supportedIssuers: values }),
    ).resolves.toEqual({ ok: false, reason: "issuer_unsupported" });
  });

  it("rejects sparse and inherited supported issuer elements", async () => {
    const sparse = Array<string>(1);
    await expect(
      load({ supportedIssuers: sparse }),
    ).resolves.toEqual({ ok: false, reason: "issuer_unsupported" });

    const inherited = [ISS];
    delete inherited[0];
    Object.setPrototypeOf(inherited, { 0: ISS });
    await expect(
      load({ supportedIssuers: inherited }),
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

  it.each([7, " ", "   ", "cail:\u0000x"])(
    "rejects nonscalar or malformed audience %j",
    async (expectedAudience) => {
      await expect(
        load({ expectedAudience }),
      ).resolves.toEqual({ ok: false, reason: "audience_malformed" });
    },
  );

  it.each([" ", "   "])(
    "rejects a matching signed token for whitespace-only audience %j at the config boundary",
    async (expectedAudience) => {
      const matchingToken = await key.mintIdentityJwt({
        audience: expectedAudience,
        subject: "cail-0123456789abcdef0123456789abcdef",
        now: NOW,
        claims: {
          sub: "cail-0123456789abcdef0123456789abcdef",
          aud: expectedAudience,
          iss: ISS,
          exp: NOW + 3600,
          iat: undefined,
        },
      });
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
    const valid: JsonObject = {
      jwks: key.jwksJson,
      issuer: ISS,
      expectedAudience: AUD,
      supportedIssuers: [ISS],
      now: NOW,
      clockToleranceSeconds: 0,
    };
    const later: JsonObject = {
      jwks: '{"keys":[]}',
      issuer: "https://evil.example/",
      expectedAudience: ["wrong"],
      supportedIssuers: [],
      now: Number.NaN,
      clockToleranceSeconds: 301,
    };
    // SAFETY: the null-prototype object is populated with every required
    // configuration accessor immediately below.
    const hostile = Object.create(null) as LoadIdentityVerifierConfigInput;
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

    const result = await loadIdentityVerifierConfig(hostile);
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
    const hostileInput = new Proxy<LoadIdentityVerifierConfigInput>(
      { jwks: undefined, issuer: undefined, expectedAudience: undefined },
      { getOwnPropertyDescriptor: throwing },
    );
    await expect(
      loadIdentityVerifierConfig(hostileInput),
    ).resolves.toEqual({ ok: false, reason: "jwks_missing" });

    const hostileAllowlist = new Proxy([ISS], { get: throwing });
    await expect(
      load({ supportedIssuers: hostileAllowlist }),
    ).resolves.toEqual({ ok: false, reason: "issuer_unsupported" });
  });

  it("rejects forged verifier objects as configuration misuse, not token failure", async () => {
    // SAFETY: this object intentionally omits the private brand to verify
    // forged verifier objects are rejected before token processing.
    await expect(
      verifyIdentityJwt(
        "a.b.c",
        {
          expectedAudience: AUD,
          issuer: ISS,
          clockToleranceSeconds: 60,
          keyIds: [key.kid],
        } as never,
      ),
    ).rejects.toThrow("snapshot returned by loadIdentityVerifierConfig");
  });
});
