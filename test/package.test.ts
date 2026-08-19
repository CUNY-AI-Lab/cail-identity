import { beforeAll, describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import {
  CAIL_CANONICAL_ISSUER,
  deriveAppSubject,
  deriveCailSubject,
  isAppSubject,
  isCailSubject,
  loadIdentityVerifierConfig,
  verifyIdentityJwt,
  type LoadIdentityVerifierConfigInput,
} from "@cuny-ai-lab/cail-identity";
import {
  makeRsaFixture,
  mintRsaJwt,
  type JsonObject,
  type JsonValue,
  type RsaFixture,
} from "./fixtures.js";

const NOW = 1_000_000;
const AUD = "cail:package-test";

let fixture: RsaFixture;
let packageMetadata: JsonObject;

beforeAll(async () => {
  [fixture, packageMetadata] = await Promise.all([
    makeRsaFixture("package-entry"),
    readFile(new URL("../package.json", import.meta.url), "utf8").then(
      (value) => {
        // SAFETY: package.json is the checked-in package manifest and this
        // test reads only its JSON object metadata fields below.
        return JSON.parse(value) as JsonObject;
      },
    ),
  ]);
});

function claims(aud: JsonValue = AUD): JsonObject {
  return {
    sub: "cail-fedcba9876543210fedcba9876543210",
    aud,
    iss: CAIL_CANONICAL_ISSUER,
    exp: NOW + 3600,
  };
}

function jwksWith(overrides: JsonObject): string {
  return JSON.stringify({
    keys: [{ ...fixture.publicJwk, ...overrides }],
  });
}

describe("published package entry", () => {
  it("exports the canonical verifier and issuer constants", () => {
    expect(verifyIdentityJwt).toBeTypeOf("function");
    expect(loadIdentityVerifierConfig).toBeTypeOf("function");
    expect(deriveCailSubject).toBeTypeOf("function");
    expect(isCailSubject).toBeTypeOf("function");
    expect(deriveAppSubject).toBeTypeOf("function");
    expect(isAppSubject).toBeTypeOf("function");
    expect(CAIL_CANONICAL_ISSUER).toBe(
      "https://cail-doorway.ailab-452.workers.dev/cail-sso",
    );
  });

  it("publishes to GitHub Packages under the @cuny-ai-lab scope", () => {
    expect(packageMetadata.publishConfig).toEqual({
      registry: "https://npm.pkg.github.com",
      access: "restricted",
    });
    expect(packageMetadata.repository).toEqual({
      type: "git",
      url: "git+https://github.com/CUNY-AI-Lab/cail-identity.git",
    });
  });

  it("separates invalid token audience from invalid verifier configuration", async () => {
    const arrayAudience = await mintRsaJwt(claims([AUD]), fixture);
    const loaded = await loadIdentityVerifierConfig({
      jwks: JSON.stringify(fixture.jwks),
      issuer: CAIL_CANONICAL_ISSUER,
      expectedAudience: AUD,
      now: NOW,
    });
    expect(loaded.ok).toBe(true);
    if (!loaded.ok) return;

    await expect(
      verifyIdentityJwt(arrayAudience, loaded.config),
    ).resolves.toBeNull();
    await expect(
      loadIdentityVerifierConfig({
        jwks: JSON.stringify(fixture.jwks),
        issuer: CAIL_CANONICAL_ISSUER,
        expectedAudience: AUD,
        supportedIssuers: [CAIL_CANONICAL_ISSUER, CAIL_CANONICAL_ISSUER],
        now: NOW,
      }),
    ).resolves.toEqual({ ok: false, reason: "issuer_unsupported" });
  });

  it("enforces RSA public-number eligibility through the package entry", async () => {
    const modulus = Buffer.from(fixture.publicJwk.n!, "base64url");
    expect(modulus).toHaveLength(256);
    expect(modulus[0]! & 0x80).not.toBe(0);
    expect(fixture.publicJwk.e).toBe("AQAB");
    await expect(
      loadIdentityVerifierConfig({
        jwks: JSON.stringify(fixture.jwks),
        issuer: CAIL_CANONICAL_ISSUER,
        expectedAudience: AUD,
        now: NOW,
      }),
    ).resolves.toMatchObject({ ok: true });
    await expect(
      loadIdentityVerifierConfig({
        jwks: jwksWith({ e: "Aw" }),
        issuer: CAIL_CANONICAL_ISSUER,
        expectedAudience: AUD,
        now: NOW,
      }),
    ).resolves.toMatchObject({ ok: true });

    const evenModulus = Buffer.from(modulus);
    evenModulus[evenModulus.length - 1] =
      evenModulus[evenModulus.length - 1]! & 0xfe;
    const shortModulus = Buffer.from(modulus);
    shortModulus[0] = 0x7f;
    const tooLargeSafeExponent = Buffer.from([
      0x20, 0, 0, 0, 0, 0, 1,
    ]).toString("base64url");
    const invalidNumbers = [
      { e: "AQ" },
      { e: "Ag" },
      { e: tooLargeSafeExponent },
      { n: "AQ", e: "AQAB" },
      { n: "Ag", e: "Aw" },
      { n: "AA" },
      { n: Buffer.from("arbitrary modulus bytes").toString("base64url") },
      { n: evenModulus.toString("base64url") },
      { n: shortModulus.toString("base64url") },
      { n: `${fixture.publicJwk.n!}=` },
      { e: `${fixture.publicJwk.e!}=` },
      { e: "AB" },
    ];

    for (const invalidNumber of invalidNumbers) {
      await expect(
        loadIdentityVerifierConfig({
          jwks: jwksWith(invalidNumber),
          issuer: CAIL_CANONICAL_ISSUER,
          expectedAudience: AUD,
          now: NOW,
        }),
      ).resolves.toEqual({ ok: false, reason: "jwks_malformed" });
    }
  });

  it("retains duplicate, private, issuer, and timing guards through the package entry", async () => {
    const malformedJwks = [
      JSON.stringify({
        keys: [fixture.publicJwk, { ...fixture.publicJwk }],
      }),
      jwksWith({ d: "private-material" }),
    ];
    for (const jwks of malformedJwks) {
      await expect(
        loadIdentityVerifierConfig({
          jwks,
          issuer: CAIL_CANONICAL_ISSUER,
          expectedAudience: AUD,
          now: NOW,
        }),
      ).resolves.toEqual({ ok: false, reason: "jwks_malformed" });
    }

    await expect(
      loadIdentityVerifierConfig({
        jwks: JSON.stringify(fixture.jwks),
        issuer: "https://evil.example/cail-sso",
        expectedAudience: AUD,
        now: NOW,
      }),
    ).resolves.toEqual({ ok: false, reason: "issuer_unsupported" });
    await expect(
      loadIdentityVerifierConfig({
        jwks: JSON.stringify(fixture.jwks),
        issuer: CAIL_CANONICAL_ISSUER,
        expectedAudience: AUD,
        clockToleranceSeconds: 301,
      }),
    ).resolves.toEqual({ ok: false, reason: "timing_invalid" });
  });

  it("rejects whitespace-only audience through the package entry", async () => {
    for (const expectedAudience of [" ", "   "]) {
      const matchingToken = await mintRsaJwt(
        claims(expectedAudience),
        fixture,
      );
      const loaded = await loadIdentityVerifierConfig({
        jwks: JSON.stringify(fixture.jwks),
        issuer: CAIL_CANONICAL_ISSUER,
        expectedAudience,
        now: NOW,
      });
      expect(loaded).toEqual({ ok: false, reason: "audience_malformed" });

      const validConfig = await loadIdentityVerifierConfig({
        jwks: JSON.stringify(fixture.jwks),
        issuer: CAIL_CANONICAL_ISSUER,
        expectedAudience: AUD,
        now: NOW,
      });
      expect(validConfig.ok).toBe(true);
      if (validConfig.ok) {
        await expect(
          verifyIdentityJwt(matchingToken, validConfig.config),
        ).resolves.toBeNull();
      }
    }
  });

  it("reads hostile config getters once through the package entry", async () => {
    const counts = new Map<string, number>();
    const first: JsonObject = {
      jwks: JSON.stringify(fixture.jwks),
      issuer: CAIL_CANONICAL_ISSUER,
      expectedAudience: AUD,
      supportedIssuers: [CAIL_CANONICAL_ISSUER],
      now: NOW,
      clockToleranceSeconds: 0,
    };
    // SAFETY: the null-prototype object is populated with all required config
    // accessors immediately below to exercise the snapshot boundary.
    const hostile = Object.create(null) as LoadIdentityVerifierConfigInput;
    for (const [name, value] of Object.entries(first)) {
      Object.defineProperty(hostile, name, {
        enumerable: true,
        get() {
          const reads = (counts.get(name) ?? 0) + 1;
          counts.set(name, reads);
          return reads === 1 ? value : undefined;
        },
      });
    }

    await expect(
      loadIdentityVerifierConfig(hostile),
    ).resolves.toMatchObject({ ok: true });
    expect(Object.fromEntries(counts)).toEqual({
      jwks: 1,
      issuer: 1,
      expectedAudience: 1,
      supportedIssuers: 1,
      now: 1,
      clockToleranceSeconds: 1,
    });
  });
});
