import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  loadIdentityVerifierConfig,
  verifyIdentityJwt,
  type CailIdentity,
} from "../src/index.js";
import {
  createTestIdentityIssuer,
  type TestClaimRecord,
} from "../src/testing.js";

interface ClaimsExample {
  iss: string;
  aud: string;
  sub: string;
  log_sub: string;
  exp: number;
}

// SAFETY: this checked-in contract fixture is parsed only for the schema
// fields declared here; each test compares them against verifier behavior.
const contract = JSON.parse(
  readFileSync(
    new URL("../contract/identity-jwt-claims-v1.json", import.meta.url),
    "utf8",
  ),
) as {
  required: string[];
  properties: Record<string, { type: string }>;
  examples: ClaimsExample[];
};

const [example] = contract.examples;
const optionalClaims = Object.keys(contract.properties).filter(
  (claim) => !contract.required.includes(claim),
);

/** Where an accepted optional claim surfaces on the verified identity. */
const IDENTITY_FIELD = new Map<string, keyof CailIdentity>([
  ["log_sub", "operationalSubject"],
]);

const issuer = await createTestIdentityIssuer();

async function verifyClaims(
  base: ClaimsExample,
  claims: TestClaimRecord,
): Promise<CailIdentity | null> {
  const now = base.exp - 3_600;
  const token = await issuer.mintIdentityJwt({
    audience: base.aud,
    now,
    claims,
  });
  const loaded = await loadIdentityVerifierConfig({
    jwks: issuer.jwksJson,
    issuer: base.iss,
    expectedAudience: base.aud,
    supportedIssuers: [base.iss],
    now,
  });
  if (!loaded.ok) throw new Error(`invalid test config: ${loaded.reason}`);
  return verifyIdentityJwt(token, loaded.config);
}

describe("identity-jwt-claims-v1 contract", () => {
  it("has an identity field for every optional claim the contract declares", () => {
    expect([...IDENTITY_FIELD.keys()]).toEqual(optionalClaims);
  });

  it.each(contract.examples)(
    "verifies the contract example for audience $aud and maps its claims",
    async (value) => {
      await expect(verifyClaims(value, { ...value })).resolves.toMatchObject({
        subject: value.sub,
        operationalSubject: value.log_sub,
      });
    },
  );

  it.each(contract.required)("rejects a token missing required claim %s", async (claim) => {
    await expect(
      verifyClaims(example!, { ...example!, [claim]: undefined }),
    ).resolves.toBeNull();
  });

  it.each(optionalClaims)(
    "accepts a token missing optional claim %s and leaves it unmapped",
    async (claim) => {
      const identity = await verifyClaims(example!, {
        ...example!,
        [claim]: undefined,
      });
      expect(identity).not.toBeNull();
      expect(identity).not.toHaveProperty(IDENTITY_FIELD.get(claim)!);
    },
  );

  it.each<[string, TestClaimRecord[string]]>([
    ["sub", 42],
    ["sub", ""],
    ["sub", `${example!.sub}0`],
    ["sub", example!.sub.toUpperCase()],
    ["log_sub", 42],
    ["log_sub", ""],
    ["log_sub", `${example!.log_sub}0`],
    ["log_sub", example!.log_sub.toUpperCase()],
    ["exp", String(example!.exp)],
    ["exp", null],
  ])("rejects %s %j outside the claim schema", async (claim, value) => {
    await expect(
      verifyClaims(example!, { ...example!, [claim]: value }),
    ).resolves.toBeNull();
  });
});
