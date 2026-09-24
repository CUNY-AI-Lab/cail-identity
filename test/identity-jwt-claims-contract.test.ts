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
import { numberFrom, stringFrom } from "../src/validation.js";

interface ClaimSchema {
  type: "string" | "number";
  minLength?: number;
  pattern?: string;
}

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
  additionalProperties: boolean;
  properties: Record<string, ClaimSchema>;
  examples: ClaimsExample[];
};

const optionalClaims = Object.keys(contract.properties).filter(
  (claim) => !contract.required.includes(claim),
);

/** Where an accepted optional claim surfaces on the verified identity. */
const IDENTITY_FIELD = new Map<string, keyof CailIdentity>([
  ["log_sub", "operationalSubject"],
]);

function claimOf(example: ClaimsExample, claim: string) {
  return new Map(Object.entries(example)).get(claim);
}

async function verifyClaims(
  example: ClaimsExample,
  claims: TestClaimRecord,
): Promise<CailIdentity | null> {
  const issuer = await createTestIdentityIssuer({ issuer: example.iss });
  const now = example.exp - 3_600;
  const token = await issuer.mintIdentityJwt({
    audience: example.aud,
    now,
    claims,
  });
  const loaded = await loadIdentityVerifierConfig({
    jwks: issuer.jwksJson,
    issuer: example.iss,
    expectedAudience: example.aud,
    supportedIssuers: [example.iss],
    now,
  });
  if (!loaded.ok) throw new Error(`invalid test config: ${loaded.reason}`);
  return verifyIdentityJwt(token, loaded.config);
}

function withClaim(
  example: ClaimsExample,
  claim: string,
  value: TestClaimRecord[string],
): TestClaimRecord {
  return { ...example, [claim]: value };
}

/** Candidate values that the declared claim schema rejects. */
function violations(schema: ClaimSchema, valid: string | number | undefined) {
  const values: TestClaimRecord[string][] = [];
  if (schema.type === "string") {
    values.push(42, "");
    if (schema.pattern !== undefined) {
      values.push(`${valid}0`, String(valid).toUpperCase());
    }
  } else {
    values.push(String(valid), null);
  }
  return values.filter((value) => !satisfies(schema, value));
}

function satisfies(schema: ClaimSchema, value: TestClaimRecord[string]): boolean {
  if (schema.type === "number") return Number.isFinite(numberFrom(value));
  const text = stringFrom(value);
  if (text === undefined || text.length < (schema.minLength ?? 0)) return false;
  return schema.pattern === undefined || new RegExp(schema.pattern, "u").test(text);
}

describe("identity-jwt-claims-v1 contract", () => {
  it("verifies each contract example and maps every declared claim", async () => {
    expect([...IDENTITY_FIELD.keys()]).toEqual(optionalClaims);
    for (const example of contract.examples) {
      const identity = await verifyClaims(example, { ...example });
      expect(identity, example.aud).not.toBeNull();
      expect(identity!.subject).toBe(example.sub);
      for (const claim of optionalClaims) {
        expect(identity![IDENTITY_FIELD.get(claim)!], claim).toBe(
          claimOf(example, claim),
        );
      }
    }
  });

  it("rejects a token missing any required claim", async () => {
    const [example] = contract.examples;
    for (const claim of contract.required) {
      await expect(
        verifyClaims(example!, withClaim(example!, claim, undefined)),
        claim,
      ).resolves.toBeNull();
    }
  });

  it("accepts a token missing any optional claim and leaves it unmapped", async () => {
    const [example] = contract.examples;
    for (const claim of optionalClaims) {
      const identity = await verifyClaims(
        example!,
        withClaim(example!, claim, undefined),
      );
      expect(identity, claim).not.toBeNull();
      expect(identity!).not.toHaveProperty(IDENTITY_FIELD.get(claim)!);
    }
  });

  it("rejects a value outside each declared claim schema", async () => {
    const [example] = contract.examples;
    for (const [claim, schema] of Object.entries(contract.properties)) {
      const invalid = violations(schema, claimOf(example!, claim));
      expect(invalid.length, claim).toBeGreaterThan(0);
      for (const value of invalid) {
        await expect(
          verifyClaims(example!, withClaim(example!, claim, value)),
          `${claim}=${JSON.stringify(value)}`,
        ).resolves.toBeNull();
      }
    }
  });

  it("accepts undeclared claims because the contract allows them", async () => {
    const [example] = contract.examples;
    expect(contract.additionalProperties).toBe(true);
    await expect(
      verifyClaims(example!, { ...example!, cail_unregistered: "ignored" }),
    ).resolves.toMatchObject({ subject: example!.sub });
  });
});
