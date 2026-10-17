/**
 * The blessed test-fixture surface (`@cuny-ai-lab/cail-identity/testing`).
 *
 * Guards the exact drift this export exists to end: consumer-invented invalid
 * subjects (`cail-abc123`, `user:${email}`). Fixture subjects must be
 * deterministic, distinct, and structurally canonical — the same SHAPE
 * `deriveCailSubject` emits — and the test issuer's tokens must verify
 * through the real `verifyIdentityJwt` boundary.
 */
import { createHash } from "node:crypto";
import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";

import {
  CAIL_CANONICAL_ISSUER,
  isCailSubject,
  loadIdentityVerifierConfig,
  verifyIdentityJwt,
  type IdentityVerifierConfig,
} from "../src/index.js";
import {
  TEST_SUBJECTS,
  canonicalTestSubject,
  createTestIdentityIssuer,
  type MintTestIdentityJwtOptions,
  type TestIdentityIssuer,
} from "../src/testing.js";

const AUD = "cail:testing-fixture";
const NOW = 2_000_000;

async function configFor(
  kit: TestIdentityIssuer,
  now: number,
): Promise<IdentityVerifierConfig> {
  const result = await loadIdentityVerifierConfig({
    jwks: kit.jwksJson,
    issuer: kit.issuer,
    expectedAudience: AUD,
    supportedIssuers: [kit.issuer],
    now,
  });
  if (!result.ok) throw new Error(`fixture config failed: ${result.reason}`);
  return result.config;
}

const issuer = await createTestIdentityIssuer();
const config = await configFor(issuer, NOW);

describe("canonicalTestSubject", () => {
  it.each([
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb924...
    ["", "cail-e3b0c44298fc1c149afbf4c8996fb924"],
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223... (FIPS 180-4 vector)
    ["abc", "cail-ba7816bf8f01cfea414140de5dae2223"],
  ])("is cail- plus the first 32 hex of SHA-256(%j)", (seed, expected) => {
    expect(canonicalTestSubject(seed)).toBe(expected);
  });

  it.each([
    ["one byte", "x"],
    ["an email-like seed", "user:someone@gc.cuny.edu"],
    ["multi-byte UTF-8 across a block boundary", "é".repeat(31)],
    ["55 bytes (padding fits in one block)", "block-boundary-".padEnd(55, "a")],
    ["56 bytes (forces a second block)", "block-boundary-".padEnd(56, "a")],
    ["64 bytes (one full block)", "block-boundary-".padEnd(64, "a")],
    ["119 bytes (padding fits in two blocks)", "block-boundary-".padEnd(119, "a")],
    ["120 bytes (forces a third block)", "block-boundary-".padEnd(120, "a")],
    ["500 bytes", "long-".repeat(100)],
    ["control characters", `${String.fromCharCode(0, 1, 0x7f)} mixed controls`],
  ])("matches node:crypto SHA-256 for %s", (_name, seed) => {
    expect(canonicalTestSubject(seed)).toBe(
      `cail-${createHash("sha256").update(seed, "utf8").digest("hex").slice(0, 32)}`,
    );
  });

  // SAFETY: these deliberately inject wrong runtime values to exercise the
  // test-fixture input boundary.
  it.each([42 as never, undefined as never])("rejects non-string seed %j", (seed) => {
    expect(() => canonicalTestSubject(seed)).toThrow(TypeError);
  });
});

describe("TEST_SUBJECTS", () => {
  it.each(["alice", "bob", "carol"] as const)(
    "%s is the canonical test subject of its own name",
    (name) => {
      expect(TEST_SUBJECTS[name]).toBe(canonicalTestSubject(name));
      expect(isCailSubject(TEST_SUBJECTS[name])).toBe(true);
    },
  );
});

describe("createTestIdentityIssuer", () => {
  it("mints identity JWTs that verify through verifyIdentityJwt", async () => {
    const token = await issuer.mintIdentityJwt({
      audience: AUD,
      email: "someone@gc.cuny.edu",
      name: "Some One",
      entitlements: ["tools"],
      now: NOW,
    });
    await expect(verifyIdentityJwt(token, config)).resolves.toEqual({
      subject: TEST_SUBJECTS.alice,
      email: "someone@gc.cuny.edu",
      name: "Some One",
      entitlements: ["tools"],
    });
  });

  it("defaults to the canonical standalone issuer and exposes JWKS as object and JSON", () => {
    expect(issuer.issuer).toBe(CAIL_CANONICAL_ISSUER);
    expect(JSON.parse(issuer.jwksJson)).toEqual(issuer.jwks);
    expect(issuer.jwks.keys).toHaveLength(1);
    expect(issuer.jwks.keys[0]?.kid).toBe(issuer.kid);
  });

  it("honors kid, issuer, subject and time overrides", async () => {
    const alternate = await createTestIdentityIssuer({
      kid: "alternate-key",
      issuer: "https://test-issuer.example/cail-sso",
    });
    const token = await alternate.mintIdentityJwt({
      audience: AUD,
      subject: TEST_SUBJECTS.bob,
      now: NOW,
      expiresInSeconds: 60,
    });
    await expect(
      verifyIdentityJwt(token, await configFor(alternate, NOW + 30)),
    ).resolves.toMatchObject({ subject: TEST_SUBJECTS.bob });
  });

  it("tokens from one issuer kit never verify against another kit's JWKS", async () => {
    const other = await createTestIdentityIssuer();
    const token = await other.mintIdentityJwt({ audience: AUD, now: NOW });
    await expect(verifyIdentityJwt(token, config)).resolves.toBeNull();
  });

  // SAFETY: the second and third rows deliberately bypass the typed fixture
  // contract to exercise its runtime validation boundary.
  it.each([
    ["an empty audience", { audience: "" }],
    ["no options", undefined as never],
    ["a non-string audience array", { audience: [42] as never }],
  ])("rejects %s at mint time", async (_name, options: MintTestIdentityJwtOptions) => {
    await expect(issuer.mintIdentityJwt(options)).rejects.toThrow(TypeError);
  });

  it("mints auth_time and the token still verifies", async () => {
    const token = await issuer.mintIdentityJwt({
      audience: AUD,
      now: NOW,
      authTime: NOW - 30,
    });
    expect(decodeJwt(token).auth_time).toBe(NOW - 30);
    await expect(verifyIdentityJwt(token, config)).resolves.toMatchObject({
      subject: TEST_SUBJECTS.alice,
    });
  });

  it("mints nbf and a past-nbf token still verifies", async () => {
    const token = await issuer.mintIdentityJwt({
      audience: AUD,
      now: NOW,
      notBefore: NOW - 120,
    });
    expect(decodeJwt(token).nbf).toBe(NOW - 120);
    await expect(verifyIdentityJwt(token, config)).resolves.not.toBeNull();
  });

  it("mints an array-valued aud, even with one element", async () => {
    const token = await issuer.mintIdentityJwt({ audience: [AUD], now: NOW });
    expect(decodeJwt(token).aud).toEqual([AUD]);
  });

  it("applies claim overrides last: sets custom claims, replaces defaults and omits undefined", async () => {
    const token = await issuer.mintIdentityJwt({
      audience: AUD,
      now: NOW,
      claims: {
        acr: "urn:mace:incommon:iap:silver",
        exp: NOW + 5,
        iat: undefined,
      },
    });
    const payload = decodeJwt(token);
    expect(payload.acr).toBe("urn:mace:incommon:iap:silver");
    expect(payload.exp).toBe(NOW + 5);
    expect(payload).not.toHaveProperty("iat");
    await expect(
      verifyIdentityJwt(token, await configFor(issuer, NOW + 1)),
    ).resolves.not.toBeNull();
  });

  it("omits exp when a claim override sets it to undefined", async () => {
    const token = await issuer.mintIdentityJwt({
      audience: AUD,
      now: NOW,
      claims: { exp: undefined },
    });
    expect(decodeJwt(token)).not.toHaveProperty("exp");
  });

  it("rejects non-object claims at mint time", async () => {
    await expect(
      issuer.mintIdentityJwt({
        audience: AUD,
        // SAFETY: this deliberately passes an array at the claims boundary to
        // verify the fixture rejects a non-object override.
        claims: ["nope"] as never,
      }),
    ).rejects.toThrow(TypeError);
  });
});
