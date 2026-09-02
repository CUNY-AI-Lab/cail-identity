import { beforeAll, describe, expect, it } from "vitest";
import {
  CAIL_CANONICAL_ISSUER,
  loadIdentityVerifierConfig,
  verifyIdentityJwt,
} from "@cuny-ai-lab/cail-identity";
import {
  createTestIdentityIssuer,
  type TestIdentityIssuer,
} from "../src/testing.js";

const NOW = 1_000_000;
const AUD = "cail:package-test";

let issuer: TestIdentityIssuer;

beforeAll(async () => {
  issuer = await createTestIdentityIssuer({ kid: "package-entry" });
});

describe("published package entry", () => {
  it("verifies a valid identity through the package entry", async () => {
    const subject = "cail-fedcba9876543210fedcba9876543210";
    const token = await issuer.mintIdentityJwt({
      audience: AUD,
      subject,
      now: NOW,
    });
    const loaded = await loadIdentityVerifierConfig({
      jwks: issuer.jwksJson,
      issuer: CAIL_CANONICAL_ISSUER,
      expectedAudience: AUD,
      now: NOW,
    });
    expect(loaded.ok).toBe(true);
    if (!loaded.ok) return;

    await expect(verifyIdentityJwt(token, loaded.config)).resolves.toMatchObject({
      subject,
      entitlements: [],
    });
  });

  it("separates invalid token audience from invalid verifier configuration", async () => {
    const arrayAudience = await issuer.mintIdentityJwt({
      audience: [AUD],
      subject: "cail-fedcba9876543210fedcba9876543210",
      now: NOW,
    });
    const loaded = await loadIdentityVerifierConfig({
      jwks: issuer.jwksJson,
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
        jwks: issuer.jwksJson,
        issuer: CAIL_CANONICAL_ISSUER,
        expectedAudience: AUD,
        supportedIssuers: [CAIL_CANONICAL_ISSUER, CAIL_CANONICAL_ISSUER],
        now: NOW,
      }),
    ).resolves.toEqual({ ok: false, reason: "issuer_unsupported" });
  });
});
