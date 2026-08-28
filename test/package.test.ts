import { beforeAll, describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import {
  CAIL_AUTH_ERROR_CODES,
  CAIL_CANONICAL_ISSUER,
  createCailAuthError,
  deriveAppSubject,
  deriveCailSubject,
  parseCailAuthErrorJson,
  isAppSubject,
  isCailSubject,
  loadIdentityVerifierConfig,
  verifyIdentityJwt,
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

describe("published package entry", () => {
  it("exports the canonical verifier and issuer constants", () => {
    expect(verifyIdentityJwt).toBeTypeOf("function");
    expect(loadIdentityVerifierConfig).toBeTypeOf("function");
    expect(deriveCailSubject).toBeTypeOf("function");
    expect(isCailSubject).toBeTypeOf("function");
    expect(deriveAppSubject).toBeTypeOf("function");
    expect(isAppSubject).toBeTypeOf("function");
    expect(CAIL_CANONICAL_ISSUER).toBe(
      "https://tools.ailab.gc.cuny.edu/cail-sso",
    );
    expect(CAIL_AUTH_ERROR_CODES).toContain("authentication_required");
    expect(createCailAuthError).toBeTypeOf("function");
    expect(parseCailAuthErrorJson).toBeTypeOf("function");
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
    expect(packageMetadata).toMatchObject({
      exports: {
        "./contract/auth-error-envelope-v1.json":
          "./contract/auth-error-envelope-v1.json",
      },
    });
  });

  it("verifies a valid identity through the package entry", async () => {
    const token = await mintRsaJwt(claims(), fixture);
    const loaded = await loadIdentityVerifierConfig({
      jwks: JSON.stringify(fixture.jwks),
      issuer: CAIL_CANONICAL_ISSUER,
      expectedAudience: AUD,
      now: NOW,
    });
    expect(loaded.ok).toBe(true);
    if (!loaded.ok) return;

    await expect(verifyIdentityJwt(token, loaded.config)).resolves.toMatchObject({
      subject: claims().sub,
      entitlements: [],
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
});
