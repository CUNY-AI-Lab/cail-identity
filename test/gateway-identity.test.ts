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

const NOW = 2_000_000;

async function fixture() {
  const issuer = await createTestIdentityIssuer();
  const gateway = await loadIdentityVerifierConfig({
    jwks: issuer.jwksJson,
    issuer: issuer.issuer,
    expectedAudience: CAIL_GATEWAY_AUDIENCE,
    now: NOW,
  });
  if (!gateway.ok) throw new Error("fixture config failed");
  return { issuer, gateway: gateway.config };
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
});
