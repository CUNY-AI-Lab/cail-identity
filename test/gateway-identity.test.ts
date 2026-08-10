import { describe, expect, it } from "vitest";

import {
  CAIL_GATEWAY_AUDIENCE,
  loadIdentityVerifierConfig,
  verifyIdentityJwt,
} from "../src/index.js";
import {
  TEST_SUBJECTS,
  createTestIdentityIssuer,
} from "../src/testing.js";

const APP_AUDIENCE = "cail:site-studio";
const NOW = 2_000_000;

async function fixture() {
  const issuer = await createTestIdentityIssuer();
  const [gateway, app] = await Promise.all([
    loadIdentityVerifierConfig({
      jwks: issuer.jwksJson,
      issuer: issuer.issuer,
      expectedAudience: CAIL_GATEWAY_AUDIENCE,
      now: NOW,
    }),
    loadIdentityVerifierConfig({
      jwks: issuer.jwksJson,
      issuer: issuer.issuer,
      expectedAudience: APP_AUDIENCE,
      now: NOW,
    }),
  ]);
  if (!gateway.ok || !app.ok) throw new Error("fixture config failed");
  return { issuer, gateway: gateway.config, app: app.config };
}

describe("Gateway identity verification", () => {
  it("accepts a claimless Gateway JWT with the ordinary identity shape", async () => {
    const { issuer, gateway } = await fixture();
    const token = await issuer.mintIdentityJwt({
      audience: CAIL_GATEWAY_AUDIENCE,
      subject: TEST_SUBJECTS.alice,
      now: NOW,
    });

    await expect(verifyIdentityJwt(token, gateway)).resolves.toEqual({
      subject: TEST_SUBJECTS.alice,
      email: undefined,
      name: undefined,
      entitlements: [],
    });
  });

  it("rejects an invalid signature, audience, time, or subject", async () => {
    const { issuer, gateway } = await fixture();
    const valid = await issuer.mintIdentityJwt({
      audience: CAIL_GATEWAY_AUDIENCE,
      subject: TEST_SUBJECTS.alice,
      now: NOW,
    });
    const forged = `${valid.slice(0, -1)}${valid.endsWith("A") ? "B" : "A"}`;
    await expect(verifyIdentityJwt(forged, gateway)).resolves.toBeNull();

    const wrongAudience = await issuer.mintIdentityJwt({
      audience: APP_AUDIENCE,
      subject: TEST_SUBJECTS.alice,
      now: NOW,
    });
    await expect(verifyIdentityJwt(wrongAudience, gateway)).resolves.toBeNull();

    const expired = await issuer.mintIdentityJwt({
      audience: CAIL_GATEWAY_AUDIENCE,
      subject: TEST_SUBJECTS.alice,
      now: NOW - 3_600,
      expiresInSeconds: 1,
    });
    await expect(verifyIdentityJwt(expired, gateway)).resolves.toBeNull();

    const invalidSubject = await issuer.mintIdentityJwt({
      audience: CAIL_GATEWAY_AUDIENCE,
      subject: "cail-not-canonical",
      now: NOW,
    });
    await expect(verifyIdentityJwt(invalidSubject, gateway)).resolves.toBeNull();
  });

  it("keeps app-audience verification identity-only and ignores unknown claims", async () => {
    const { issuer, app } = await fixture();
    const token = await issuer.mintIdentityJwt({
      audience: APP_AUDIENCE,
      subject: TEST_SUBJECTS.alice,
      now: NOW,
      claims: {
        registryPolicy: "ignored",
      },
    });

    await expect(verifyIdentityJwt(token, app)).resolves.toEqual({
      subject: TEST_SUBJECTS.alice,
      email: undefined,
      name: undefined,
      entitlements: [],
    });
  });
});
