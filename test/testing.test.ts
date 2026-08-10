/**
 * The blessed test-fixture surface (`@cuny-ai-lab/cail-identity/testing`).
 *
 * Guards the exact drift this export exists to end: consumer-invented invalid
 * subjects (`cail-abc123`, `user:${email}`). Fixture subjects must be
 * deterministic, distinct, and structurally canonical — the same SHAPE
 * `deriveCailSubject` emits — and the test issuer's tokens must verify
 * through the real `verifyIdentityJwt` boundary.
 */
import { createHash, randomBytes } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";

import {
  CAIL_CANONICAL_ISSUER,
  deriveCailSubject,
  isCailSubject,
  loadIdentityVerifierConfig,
  verifyIdentityJwt,
  type IdentityVerifierConfig,
} from "../src/index.js";
import {
  TEST_SUBJECTS,
  canonicalTestSubject,
  createTestIdentityIssuer,
  type TestIdentityIssuer,
} from "../src/testing.js";

function referenceSubject(seed: string): string {
  return `cail-${createHash("sha256").update(seed, "utf8").digest("hex").slice(0, 32)}`;
}

async function configFor(
  issuer: TestIdentityIssuer,
  expectedAudience: string,
  now?: number,
): Promise<IdentityVerifierConfig> {
  const result = await loadIdentityVerifierConfig({
    jwks: issuer.jwksJson,
    issuer: issuer.issuer,
    expectedAudience,
    supportedIssuers: [issuer.issuer],
    now,
  });
  if (!result.ok) throw new Error(`fixture config failed: ${result.reason}`);
  return result.config;
}

describe("canonicalTestSubject", () => {
  it("is deterministic: the same seed always yields the same subject", () => {
    expect(canonicalTestSubject("alice")).toBe(canonicalTestSubject("alice"));
    expect(canonicalTestSubject("user:someone@gc.cuny.edu")).toBe(
      canonicalTestSubject("user:someone@gc.cuny.edu"),
    );
  });

  it("gives distinct subjects for distinct seeds", () => {
    const seeds = Array.from({ length: 200 }, (_, i) => `seed-${i}`);
    const subjects = new Set(seeds.map(canonicalTestSubject));
    expect(subjects.size).toBe(seeds.length);
  });

  it("always matches the canonical CAIL subject shape", () => {
    for (const seed of ["", "alice", "user:bob@x", "ünïcode-Σ", "a".repeat(500)]) {
      const subject = canonicalTestSubject(seed);
      expect(isCailSubject(subject)).toBe(true);
    }
  });

  it("is exactly cail- + first-32-lowercase-hex of SHA-256(seed) (FIPS vectors)", () => {
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb924...
    expect(canonicalTestSubject("")).toBe(
      "cail-e3b0c44298fc1c149afbf4c8996fb924",
    );
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223... (FIPS 180-4 vector)
    expect(canonicalTestSubject("abc")).toBe(
      "cail-ba7816bf8f01cfea414140de5dae2223",
    );
  });

  it("matches node:crypto SHA-256 over arbitrary inputs (multi-block, unicode, binary-ish)", () => {
    const seeds: string[] = [
      "x",
      "user:someone@gc.cuny.edu",
      "é".repeat(31), // multi-byte UTF-8 straddling block boundaries
      "block-boundary-".padEnd(55, "a"), // 55 bytes: padding fits in one block
      "block-boundary-".padEnd(56, "a"), // 56 bytes: forces a second block
      "block-boundary-".padEnd(64, "a"), // exactly one full block of message
      "long-".repeat(100),
      `${String.fromCharCode(0, 1, 0x7f)} mixed controls`,
    ];
    for (let i = 0; i < 64; i++) {
      seeds.push(randomBytes(1 + (i % 97)).toString("base64"));
    }
    for (const seed of seeds) {
      expect(canonicalTestSubject(seed)).toBe(referenceSubject(seed));
    }
  });

  it("shares the exact shape deriveCailSubject produces", async () => {
    const derived = await deriveCailSubject({
      issuer: CAIL_CANONICAL_ISSUER,
      oidcSubject: "someone",
      subjectSalt: "test-only-salt-at-least-32-bytes-long",
    });
    const fixture = canonicalTestSubject("someone");
    expect(isCailSubject(fixture)).toBe(true);
    expect(isCailSubject(derived)).toBe(true);
    expect(fixture.length).toBe(derived.length);
  });

  it("rejects non-string seeds", () => {
    expect(() => canonicalTestSubject(42 as unknown as string)).toThrow(
      TypeError,
    );
    expect(() =>
      canonicalTestSubject(undefined as unknown as string),
    ).toThrow(TypeError);
  });
});

describe("TEST_SUBJECTS", () => {
  it("are distinct canonical subjects derived from their own names", () => {
    expect(TEST_SUBJECTS.alice).toBe(canonicalTestSubject("alice"));
    expect(TEST_SUBJECTS.bob).toBe(canonicalTestSubject("bob"));
    expect(TEST_SUBJECTS.carol).toBe(canonicalTestSubject("carol"));
    const all = Object.values(TEST_SUBJECTS);
    expect(new Set(all).size).toBe(all.length);
    for (const subject of all) expect(isCailSubject(subject)).toBe(true);
  });
});

describe("createTestIdentityIssuer", () => {
  const AUD = "cail:testing-fixture";
  let issuer: TestIdentityIssuer;
  let config: IdentityVerifierConfig;

  beforeAll(async () => {
    issuer = await createTestIdentityIssuer();
    config = await configFor(issuer, AUD);
  });

  it("mints identity JWTs that verify through verifyIdentityJwt", async () => {
    const token = await issuer.mintIdentityJwt({
      audience: AUD,
      email: "someone@gc.cuny.edu",
      name: "Some One",
      entitlements: ["tools"],
    });
    const identity = await verifyIdentityJwt(token, config);
    expect(identity).not.toBeNull();
    expect(identity?.subject).toBe(TEST_SUBJECTS.alice);
    expect(identity?.email).toBe("someone@gc.cuny.edu");
    expect(identity?.name).toBe("Some One");
    expect(identity?.entitlements).toEqual(["tools"]);
  });

  it("defaults to the canonical standalone issuer and exposes JWKS as object and JSON", async () => {
    expect(issuer.issuer).toBe(CAIL_CANONICAL_ISSUER);
    expect(JSON.parse(issuer.jwksJson)).toEqual(issuer.jwks);
    expect(issuer.jwks.keys).toHaveLength(1);
    expect(issuer.jwks.keys[0]?.kid).toBe(issuer.kid);
  });

  it("honors subject / issuer / time overrides (and fail-closed paths stay reachable)", async () => {
    const alternate = await createTestIdentityIssuer({
      kid: "alternate-key",
      issuer: "https://test-issuer.example/cail-sso",
    });
    const now = 1_000_000;
    const token = await alternate.mintIdentityJwt({
      audience: AUD,
      subject: TEST_SUBJECTS.bob,
      now,
      expiresInSeconds: 60,
    });
    const activeConfig = await configFor(alternate, AUD, now + 30);
    await expect(
      verifyIdentityJwt(token, activeConfig),
    ).resolves.toMatchObject({ subject: TEST_SUBJECTS.bob });
    // Expired by the verifier's clock → null.
    const expiredConfig = await configFor(alternate, AUD, now + 3600);
    await expect(
      verifyIdentityJwt(token, expiredConfig),
    ).resolves.toBeNull();
  });

  it("can mint the historically-invalid subjects so fail-closed tests keep working", async () => {
    const token = await issuer.mintIdentityJwt({
      audience: AUD,
      subject: "cail-abc123", // the exact drift class this export retires
    });
    await expect(
      verifyIdentityJwt(token, config),
    ).resolves.toBeNull();
  });

  it("tokens from one issuer kit never verify against another kit's JWKS", async () => {
    const other = await createTestIdentityIssuer();
    const token = await other.mintIdentityJwt({ audience: AUD });
    await expect(
      verifyIdentityJwt(token, config),
    ).resolves.toBeNull();
  });

  it("rejects a missing or empty audience at mint time", async () => {
    await expect(
      issuer.mintIdentityJwt({ audience: "" }),
    ).rejects.toThrow(TypeError);
    await expect(
      issuer.mintIdentityJwt(undefined as unknown as { audience: string }),
    ).rejects.toThrow(TypeError);
    await expect(
      issuer.mintIdentityJwt({ audience: [42] as unknown as string[] }),
    ).rejects.toThrow(TypeError);
  });

  function decodePayload(token: string): Record<string, unknown> {
    const part = token.split(".")[1]!;
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(Buffer.from(b64, "base64").toString("utf8"));
  }

  it("mints auth_time and the token still verifies (session-binding contracts)", async () => {
    const now = 2_000_000;
    const token = await issuer.mintIdentityJwt({
      audience: AUD,
      now,
      authTime: now - 30,
    });
    expect(decodePayload(token).auth_time).toBe(now - 30);
    const timedConfig = await configFor(issuer, AUD, now + 10);
    await expect(
      verifyIdentityJwt(token, timedConfig),
    ).resolves.toMatchObject({ subject: TEST_SUBJECTS.alice });
  });

  it("mints nbf: past-nbf tokens verify, future-nbf tokens are rejected", async () => {
    const now = 2_000_000;
    const timedConfig = await configFor(issuer, AUD, now);
    const active = await issuer.mintIdentityJwt({
      audience: AUD,
      now,
      notBefore: now - 120,
    });
    expect(decodePayload(active).nbf).toBe(now - 120);
    await expect(verifyIdentityJwt(active, timedConfig)).resolves.not.toBeNull();

    const notYetValid = await issuer.mintIdentityJwt({
      audience: AUD,
      now,
      notBefore: now + 3600,
    });
    await expect(verifyIdentityJwt(notYetValid, timedConfig)).resolves.toBeNull();
  });

  it("mints array-valued aud (even one-element) that the verifier must reject", async () => {
    const token = await issuer.mintIdentityJwt({ audience: [AUD] });
    expect(decodePayload(token).aud).toEqual([AUD]);
    await expect(
      verifyIdentityJwt(token, config),
    ).resolves.toBeNull();
  });

  it("accepts arbitrary claim overrides: set registered/custom claims and omit defaults", async () => {
    const now = 2_000_000;
    const token = await issuer.mintIdentityJwt({
      audience: AUD,
      now,
      claims: {
        acr: "urn:mace:incommon:iap:silver", // custom registered claim
        exp: now + 5, // overrides expiresInSeconds default
        iat: undefined, // omitted entirely
      },
    });
    const payload = decodePayload(token);
    expect(payload.acr).toBe("urn:mace:incommon:iap:silver");
    expect(payload.exp).toBe(now + 5);
    expect("iat" in payload).toBe(false);
    // Still a REAL RS256 token: verifies within its (overridden) lifetime...
    const activeConfig = await configFor(issuer, AUD, now + 1);
    await expect(
      verifyIdentityJwt(token, activeConfig),
    ).resolves.not.toBeNull();
    // ...and a token with `exp` omitted via claims is rejected (exp required).
    const noExp = await issuer.mintIdentityJwt({
      audience: AUD,
      now,
      claims: { exp: undefined },
    });
    expect("exp" in decodePayload(noExp)).toBe(false);
    const expiredConfig = await configFor(issuer, AUD, now);
    await expect(
      verifyIdentityJwt(noExp, expiredConfig),
    ).resolves.toBeNull();
  });

  it("rejects non-object claims at mint time", async () => {
    await expect(
      issuer.mintIdentityJwt({
        audience: AUD,
        claims: ["nope"] as unknown as Record<string, unknown>,
      }),
    ).rejects.toThrow(TypeError);
  });
});

describe("published testing subpath", () => {
  it("resolves @cuny-ai-lab/cail-identity/testing via the exports map", async () => {
    const viaPackage = await import("@cuny-ai-lab/cail-identity/testing");
    expect(viaPackage.canonicalTestSubject).toBeTypeOf("function");
    expect(viaPackage.createTestIdentityIssuer).toBeTypeOf("function");
    expect(viaPackage.TEST_SUBJECTS.alice).toBe(TEST_SUBJECTS.alice);
  });
});
