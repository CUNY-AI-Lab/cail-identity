import { describe, expect, it } from "vitest";

import {
  CAIL_BUDGET_SCOPE_CLAIM,
  CAIL_BUDGET_SCOPES,
  CAIL_CANONICAL_ISSUER,
  CAIL_GATEWAY_AUDIENCE,
  CAIL_MODEL_SCOPES,
  loadIdentityVerifierConfig,
  verifyIdentityJwt,
} from "../src/index.js";
import {
  TEST_SUBJECTS,
  createTestIdentityIssuer,
} from "../src/testing.js";

const APP_AUDIENCE = "cail:gateway-access-test";
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

describe("signed Gateway access claims", () => {
  it("exports frozen vocabularies and the namespaced budget claim", () => {
    expect(CAIL_MODEL_SCOPES).toEqual([
      "models:read",
      "models:invoke",
      "quota:read",
    ]);
    expect(CAIL_BUDGET_SCOPES).toEqual([
      "person",
      "classroom",
      "person-plus",
      "admin",
    ]);
    expect(Object.isFrozen(CAIL_MODEL_SCOPES)).toBe(true);
    expect(Object.isFrozen(CAIL_BUDGET_SCOPES)).toBe(true);
    expect(CAIL_BUDGET_SCOPE_CLAIM).toBe(
      "https://ailab.gc.cuny.edu/claims/budget_scope",
    );
  });

  it("mints and returns the complete typed gateway access projection", async () => {
    const { issuer, gateway } = await fixture();
    const token = await issuer.mintIdentityJwt({
      audience: CAIL_GATEWAY_AUDIENCE,
      subject: TEST_SUBJECTS.alice,
      now: NOW,
      gatewayAccess: {
        scopes: ["models:invoke", "quota:read"],
        budgetScope: "classroom",
      },
    });
    const identity = await verifyIdentityJwt(token, gateway);
    expect(identity).toMatchObject({
      subject: TEST_SUBJECTS.alice,
      scopes: ["models:invoke", "quota:read"],
      budgetScope: "classroom",
    });
    expect(identity?.scopes).toEqual(["models:invoke", "quota:read"]);
  });

  it("requires both access claims for the exact gateway audience", async () => {
    const { issuer, gateway } = await fixture();
    for (const claims of [
      {},
      { scope: "models:read" },
      { [CAIL_BUDGET_SCOPE_CLAIM]: "person" },
    ]) {
      const token = await issuer.mintIdentityJwt({
        audience: CAIL_GATEWAY_AUDIENCE,
        now: NOW,
        claims,
      });
      await expect(verifyIdentityJwt(token, gateway)).resolves.toBeNull();
    }
  });

  it.each([
    "models:read models:read",
    "models:read unknown",
    "models:read  models:invoke",
    "models:read\tmodels:invoke",
    " models:read",
    "models:read ",
    "",
  ])("rejects malformed or unauthorized scope %j", async (scope) => {
    const { issuer, gateway } = await fixture();
    const token = await issuer.mintIdentityJwt({
      audience: CAIL_GATEWAY_AUDIENCE,
      now: NOW,
      claims: {
        scope,
        [CAIL_BUDGET_SCOPE_CLAIM]: "person",
      },
    });
    await expect(verifyIdentityJwt(token, gateway)).resolves.toBeNull();
  });

  it.each(["app", "", "unknown", 42, null, {}])(
    "rejects malformed or forbidden budget scope %j",
    async (budgetScope) => {
      const { issuer, gateway } = await fixture();
      const token = await issuer.mintIdentityJwt({
        audience: CAIL_GATEWAY_AUDIENCE,
        now: NOW,
        claims: {
          scope: "models:read",
          [CAIL_BUDGET_SCOPE_CLAIM]: budgetScope,
        },
      });
      await expect(verifyIdentityJwt(token, gateway)).resolves.toBeNull();
    },
  );

  it("rejects an array-shaped budget scope even when its item is known", async () => {
    const { issuer, gateway } = await fixture();
    const token = await issuer.mintIdentityJwt({
      audience: CAIL_GATEWAY_AUDIENCE,
      now: NOW,
      claims: {
        scope: "models:read",
        [CAIL_BUDGET_SCOPE_CLAIM]: ["person"],
      },
    });
    await expect(verifyIdentityJwt(token, gateway)).resolves.toBeNull();
  });

  it("does not treat app-audience access claims as authority", async () => {
    const { issuer, app } = await fixture();
    const token = await issuer.mintIdentityJwt({
      audience: APP_AUDIENCE,
      now: NOW,
      claims: {
        scope: "unknown unknown",
        [CAIL_BUDGET_SCOPE_CLAIM]: "app",
      },
    });
    const identity = await verifyIdentityJwt(token, app);
    expect(identity).not.toBeNull();
    expect(identity).not.toHaveProperty("scopes");
    expect(identity).not.toHaveProperty("budgetScope");
  });

  it("does not inherit access claims from a claims object's prototype", async () => {
    const { issuer, gateway } = await fixture();
    const inherited = Object.create({
      scope: "models:read",
      [CAIL_BUDGET_SCOPE_CLAIM]: "person",
    }) as Record<string, unknown>;
    const token = await issuer.mintIdentityJwt({
      audience: CAIL_GATEWAY_AUDIENCE,
      now: NOW,
      claims: inherited,
    });
    await expect(verifyIdentityJwt(token, gateway)).resolves.toBeNull();
  });
});
