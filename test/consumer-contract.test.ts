import { beforeAll, describe, expect, it } from "vitest";

import {
  loadIdentityVerifierConfig,
  verifyIdentityJwt,
  type IdentityVerifierConfigErrorReason,
} from "../src/index.js";
import {
  TEST_SUBJECTS,
  createTestIdentityIssuer,
  type TestIdentityIssuer,
} from "../src/testing.js";

const AUDIENCE = "cail:consumer-contract";

interface ConsumerResult {
  status: 200 | 401 | 503;
  configError?: IdentityVerifierConfigErrorReason;
}

async function authenticateLikeAConsumer(
  token: string,
  env: { jwks?: string; issuer?: string },
  expectedAudience: string | undefined,
): Promise<ConsumerResult> {
  const loaded = await loadIdentityVerifierConfig({
    jwks: env.jwks,
    issuer: env.issuer,
    expectedAudience,
  });
  if (!loaded.ok) {
    return { status: 503, configError: loaded.reason };
  }
  const identity = await verifyIdentityJwt(token, loaded.config);
  return { status: identity === null ? 401 : 200 };
}

describe("consumer config-error handoff contract", () => {
  let issuer: TestIdentityIssuer;
  let validToken: string;

  beforeAll(async () => {
    issuer = await createTestIdentityIssuer();
    validToken = await issuer.mintIdentityJwt({
      audience: AUDIENCE,
      subject: TEST_SUBJECTS.alice,
    });
  });

  it("maps a valid token plus invalid service config to service unavailable", async () => {
    await expect(
      authenticateLikeAConsumer(
        validToken,
        { jwks: '{"keys":[]}', issuer: issuer.issuer },
        AUDIENCE,
      ),
    ).resolves.toEqual({ status: 503, configError: "jwks_malformed" });
  });

  it("keeps missing audience inside config-error authority", async () => {
    await expect(
      authenticateLikeAConsumer(
        validToken,
        { jwks: issuer.jwksJson, issuer: issuer.issuer },
        undefined,
      ),
    ).resolves.toEqual({ status: 503, configError: "audience_missing" });
  });

  it("maps an invalid token under valid config to credential failure", async () => {
    const invalidToken =
      validToken.slice(0, -1) + (validToken.endsWith("A") ? "B" : "A");
    await expect(
      authenticateLikeAConsumer(
        invalidToken,
        { jwks: issuer.jwksJson, issuer: issuer.issuer },
        AUDIENCE,
      ),
    ).resolves.toEqual({ status: 401 });
  });

  it("accepts a valid token under valid config", async () => {
    await expect(
      authenticateLikeAConsumer(
        validToken,
        { jwks: issuer.jwksJson, issuer: issuer.issuer },
        AUDIENCE,
      ),
    ).resolves.toEqual({ status: 200 });
  });
});
