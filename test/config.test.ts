import { describe, expect, it } from "vitest";

import {
  CAIL_CANONICAL_ISSUER,
  loadIdentityVerifierConfig,
  verifyIdentityJwt,
  type IdentityVerifierConfig,
  type LoadIdentityVerifierConfigInput,
} from "../src/index.js";
import {
  makeRsaFixture,
  mintRsaJwt,
  type JsonObject,
  type JsonValue,
} from "./fixtures.js";

const NOW = 1_000_000;
const ISS = CAIL_CANONICAL_ISSUER;
const OTHER_ISS = "https://test-issuer.example/cail-sso";
const AUD = "cail-internal";
const MAX_JWKS_JSON_DEPTH = 64;

const [key, otherKey] = await Promise.all([
  makeRsaFixture("config-2026-07"),
  makeRsaFixture("config-2026-08"),
]);
const { n, e } = key.publicJwk;

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
    jwks: JSON.stringify(key.jwks),
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

function jwksWithKey(over: JsonObject): string {
  return JSON.stringify({ keys: [{ ...key.publicJwk, ...over }] });
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
    keys: [key.publicJwk],
    metadata: valueAtJwksDepth(depth),
  });
}

function base64urlBytes(bytes: number[]): string {
  return Buffer.from(bytes).toString("base64url");
}

const modulus = [...Buffer.from(n!, "base64url")];
const evenModulus = base64urlBytes([...modulus.slice(0, -1), modulus.at(-1)! & 0xfe]);
const shortModulus = base64urlBytes([0x7f, ...modulus.slice(1)]);

describe("loadIdentityVerifierConfig happy path", () => {
  it("returns a frozen full verifier snapshot", async () => {
    const config = await mustLoad();
    expect(config).toMatchObject({
      expectedAudience: AUD,
      issuer: ISS,
      clockToleranceSeconds: 60,
      keyIds: [key.kid],
    });
    expect(Object.isFrozen(config)).toBe(true);
    expect(Object.isFrozen(config.keyIds)).toBe(true);
  });

  it.each([
    ["first", key],
    ["second", otherKey],
  ])("verifies a token from the %s key of a distinct-kid rotation overlap", async (_name, signer) => {
    const config = await mustLoad({
      jwks: JSON.stringify({ keys: [key.publicJwk, otherKey.publicJwk] }),
    });
    const token = await mintRsaJwt(
      {
        sub: "cail-0123456789abcdef0123456789abcdef",
        aud: AUD,
        iss: ISS,
        exp: NOW + 3600,
      },
      signer,
    );
    await expect(verifyIdentityJwt(token, config)).resolves.not.toBeNull();
  });

  it("loads an additional issuer only when the caller explicitly trusts it", async () => {
    await expect(
      load({ issuer: OTHER_ISS, supportedIssuers: [ISS, OTHER_ISS] }),
    ).resolves.toMatchObject({ ok: true, config: { issuer: OTHER_ISS } });
  });

  it("accepts the smallest valid public exponent", async () => {
    await expect(load({ jwks: jwksWithKey({ e: "Aw" }) })).resolves.toMatchObject({
      ok: true,
    });
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
    ["null keys", '{"keys": null}'],
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
    const jwks = `{"keys":[${JSON.stringify(key.publicJwk)}],"metadata":${nested}}`;
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
          keys: [key.publicJwk],
          metadata,
          "urn:example:extension": { enabled: true },
        }),
      }),
    ).resolves.toMatchObject({ ok: true });
  });

  it.each([
    ["a missing kid", jwksWithKey({ kid: undefined })],
    ["an empty kid", jwksWithKey({ kid: "" })],
    ["a duplicate kid", JSON.stringify({ keys: [key.publicJwk, key.publicJwk] })],
  ])("flags a key with %s", async (_name, jwks) => {
    await expect(load({ jwks })).resolves.toEqual({
      ok: false,
      reason: "jwks_malformed",
    });
  });

  it.each<[string, JsonObject]>([
    ["non-RSA kty", { kty: "EC" }],
    ["non-RS256 alg", { alg: "RS512" }],
    ["encryption use", { use: "enc" }],
    ["key_ops without verify", { key_ops: ["sign"] }],
    ["duplicate key_ops", { key_ops: ["verify", "verify"] }],
    ["empty modulus", { n: "" }],
    ["private exponent", { d: "private-material" }],
    ["symmetric key material", { k: "c2VjcmV0LWtleQ" }],
    ["other primes", { oth: [] }],
  ])("flags an ineligible or private JWK: %s", async (_name, over) => {
    await expect(load({ jwks: jwksWithKey(over) })).resolves.toEqual({
      ok: false,
      reason: "jwks_malformed",
    });
  });

  it.each<[string, JsonObject]>([
    ["exponent 1", { e: "AQ" }],
    ["exponent 2", { e: "Ag" }],
    ["exponent above the safe-integer bound", { e: base64urlBytes([0x20, 0, 0, 0, 0, 0, 1]) }],
    ["tiny odd modulus", { n: "AQ", e: "AQAB" }],
    ["tiny even modulus", { n: "Ag", e: "Aw" }],
    ["zero modulus", { n: "AA" }],
    ["short arbitrary modulus", { n: Buffer.from("arbitrary modulus bytes").toString("base64url") }],
    ["even 2048-bit modulus", { n: evenModulus }],
    ["2047-bit modulus", { n: shortModulus }],
  ])("flags unusable RSA public numbers before import: %s", async (_name, over) => {
    await expect(load({ jwks: jwksWithKey(over) })).resolves.toEqual({
      ok: false,
      reason: "jwks_malformed",
    });
  });

  it.each<[string, JsonObject]>([
    ["padded modulus", { n: `${n!}=` }],
    ["padded exponent", { e: `${e!}=` }],
    ["non-base64url modulus character", { n: `+${n!.slice(1)}` }],
    ["non-canonical exponent", { e: "AB" }],
    ["modulus with a leading zero octet", { n: base64urlBytes([0, ...modulus]) }],
    ["exponent with a leading zero octet", { e: base64urlBytes([0, ...Buffer.from(e!, "base64url")]) }],
  ])("flags a malformed RSA public-number encoding: %s", async (_name, over) => {
    await expect(load({ jwks: jwksWithKey(over) })).resolves.toEqual({
      ok: false,
      reason: "jwks_malformed",
    });
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

  it.each([
    ["the default authority", undefined],
    ["a supplied authority", [ISS, OTHER_ISS]],
  ])("rejects an issuer outside %s", async (_name, supportedIssuers) => {
    await expect(
      load({ issuer: "https://evil.example/cail-sso", supportedIssuers }),
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

  it("rejects a sparse supported issuer element", async () => {
    await expect(
      load({ supportedIssuers: Array<string>(1) }),
    ).resolves.toEqual({ ok: false, reason: "issuer_unsupported" });
  });

  it("rejects an inherited supported issuer element", async () => {
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
    await expect(
      load({ now: 8_640_000_000_000, clockToleranceSeconds: 0 }),
    ).resolves.toMatchObject({ ok: true, config: { clockToleranceSeconds: 0 } });
  });
});

describe("immutable snapshots and hostile accessors", () => {
  it("loads a frozen input without writing to it", async () => {
    const frozen = Object.freeze({
      jwks: JSON.stringify(key.jwks),
      issuer: ISS,
      expectedAudience: AUD,
      supportedIssuers: Object.freeze([ISS]),
      now: NOW,
      clockToleranceSeconds: 0,
    });
    await expect(loadIdentityVerifierConfig(frozen)).resolves.toMatchObject({
      ok: true,
    });
  });

  it("leaves an ordinary input unchanged", async () => {
    const options = {
      jwks: JSON.stringify(key.jwks),
      issuer: ISS,
      expectedAudience: AUD,
      supportedIssuers: [ISS],
      now: NOW,
      clockToleranceSeconds: 0,
    };
    const before = structuredClone(options);
    await expect(loadIdentityVerifierConfig(options)).resolves.toMatchObject({
      ok: true,
    });
    expect(options).toStrictEqual(before);
  });

  it("reads every top-level option exactly once and uses those exact values", async () => {
    const counts = new Map<string, number>();
    const valid: JsonObject = {
      jwks: JSON.stringify(key.jwks),
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

  it("returns an owned config error for an input proxy that throws", async () => {
    const hostileInput = new Proxy<LoadIdentityVerifierConfigInput>(
      { jwks: undefined, issuer: undefined, expectedAudience: undefined },
      {
        getOwnPropertyDescriptor() {
          throw new Error("hostile config input");
        },
      },
    );
    await expect(
      loadIdentityVerifierConfig(hostileInput),
    ).resolves.toEqual({ ok: false, reason: "jwks_missing" });
  });

  it("returns an owned config error for a supported-issuer proxy that throws", async () => {
    const hostileAllowlist = new Proxy([ISS], {
      get() {
        throw new Error("hostile config input");
      },
    });
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
    ).rejects.toThrow(TypeError);
  });
});
