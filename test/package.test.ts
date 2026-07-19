import { beforeAll, describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import {
  CAIL_CANONICAL_ISSUER,
  CAIL_STAGING_ISSUER,
  deriveAppSubject,
  deriveCailSubject,
  isAppSubject,
  isCailSubject,
  verifyIdentityJwt,
} from "@cuny-ai-lab/cail-identity";
import { makeRsaFixture, mintRsaJwt, type RsaFixture } from "./fixtures.js";

const NOW = 1_000_000;
const AUD = "cail:package-test";

let fixture: RsaFixture;
let packageMetadata: Record<string, unknown>;

beforeAll(async () => {
  [fixture, packageMetadata] = await Promise.all([
    makeRsaFixture("package-entry"),
    readFile(new URL("../package.json", import.meta.url), "utf8").then(
      (value) => JSON.parse(value) as Record<string, unknown>,
    ),
  ]);
});

function claims(aud: unknown = AUD) {
  return {
    sub: "cail-fedcba9876543210fedcba9876543210",
    aud,
    iss: CAIL_CANONICAL_ISSUER,
    exp: NOW + 3600,
  };
}

describe("published package entry", () => {
  it("exports the canonical verifier and issuer constants", () => {
    expect(verifyIdentityJwt).toBeTypeOf("function");
    expect(deriveCailSubject).toBeTypeOf("function");
    expect(isCailSubject).toBeTypeOf("function");
    expect(deriveAppSubject).toBeTypeOf("function");
    expect(isAppSubject).toBeTypeOf("function");
    expect(CAIL_CANONICAL_ISSUER).toBe(
      "https://tools.ailab.gc.cuny.edu/cail-sso",
    );
    expect(CAIL_STAGING_ISSUER).toBe("https://tools.cuny.qzz.io/cail-sso");
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

  it("fails closed for ambiguous issuer and audience configuration", async () => {
    const arrayAudience = await mintRsaJwt(claims([AUD]), fixture);
    const multipleIssuers = await mintRsaJwt(claims(), fixture);

    await expect(
      verifyIdentityJwt(arrayAudience, fixture.jwks, {
        expectedAudience: AUD,
        allowedIssuers: [CAIL_CANONICAL_ISSUER],
        now: NOW,
      }),
    ).resolves.toBeNull();
    await expect(
      verifyIdentityJwt(multipleIssuers, fixture.jwks, {
        expectedAudience: AUD,
        allowedIssuers: [CAIL_CANONICAL_ISSUER, CAIL_STAGING_ISSUER],
        now: NOW,
      }),
    ).resolves.toBeNull();
  });
});
