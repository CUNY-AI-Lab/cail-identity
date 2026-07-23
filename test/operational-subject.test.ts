import { describe, expect, it } from "vitest";

import {
  deriveCailOperationalSubject,
  deriveCailSubject,
  isCailOperationalSubject,
  loadIdentityVerifierConfig,
  verifyIdentityJwt,
  type IdentityVerifierConfig,
} from "../src/index.js";
import {
  TEST_OPERATIONAL_SUBJECTS,
  TEST_SUBJECTS,
  createTestIdentityIssuer,
} from "../src/testing.js";

async function configFor(
  issuer: Awaited<ReturnType<typeof createTestIdentityIssuer>>,
  expectedAudience: string,
): Promise<IdentityVerifierConfig> {
  const result = await loadIdentityVerifierConfig({
    jwks: issuer.jwksJson,
    issuer: issuer.issuer,
    expectedAudience,
  });
  if (!result.ok) throw new Error(`fixture config failed: ${result.reason}`);
  return result.config;
}

describe("operational identity pseudonym", () => {
  it("uses a separate keyed and domain-separated derivation", async () => {
    const ownership = await deriveCailSubject({
      issuer: "https://issuer.example",
      oidcSubject: "ALICE@login.cuny.edu",
      subjectSalt: "ownership-salt-at-least-32-bytes-long",
    });
    const operational = await deriveCailOperationalSubject({
      issuer: "https://issuer.example",
      oidcSubject: "ALICE@login.cuny.edu",
      operationalSubjectSalt: "operational-salt-at-least-32-bytes",
    });
    expect(isCailOperationalSubject(operational)).toBe(true);
    expect(operational.slice("cail-v1-".length)).not.toBe(
      ownership.slice("cail-".length),
    );
  });

  it("snapshots operational options and exact salt bytes once", async () => {
    const reads = {
      issuer: 0,
      oidcSubject: 0,
      operationalSubjectSalt: 0,
    };
    const valid = {
      issuer: "https://issuer.example",
      oidcSubject: "ALICE@login.cuny.edu",
      operationalSubjectSalt: "operational-salt-at-least-32-bytes",
    };
    const hostile = Object.create(null) as Record<string, unknown>;
    for (const name of Object.keys(valid) as Array<keyof typeof valid>) {
      Object.defineProperty(hostile, name, {
        enumerable: true,
        get() {
          reads[name] += 1;
          return reads[name] === 1 ? valid[name] : "short";
        },
      });
    }
    const expected = await deriveCailOperationalSubject(valid);
    await expect(
      deriveCailOperationalSubject(
        hostile as unknown as Parameters<
          typeof deriveCailOperationalSubject
        >[0],
      ),
    ).resolves.toBe(expected);
    expect(reads).toEqual({
      issuer: 1,
      oidcSubject: 1,
      operationalSubjectSalt: 1,
    });
  });

  it("returns a validated optional log_sub claim from a signed token", async () => {
    const issuer = await createTestIdentityIssuer();
    const token = await issuer.mintIdentityJwt({
      audience: "cail:workbench",
      subject: TEST_SUBJECTS.alice,
      operationalSubject: TEST_OPERATIONAL_SUBJECTS.alice,
    });
    const config = await configFor(issuer, "cail:workbench");
    await expect(
      verifyIdentityJwt(token, config),
    ).resolves.toMatchObject({
      subject: TEST_SUBJECTS.alice,
      operationalSubject: TEST_OPERATIONAL_SUBJECTS.alice,
    });
  });

  it("rejects a malformed log_sub claim", async () => {
    const issuer = await createTestIdentityIssuer();
    const token = await issuer.mintIdentityJwt({
      audience: "cail:workbench",
      operationalSubject: TEST_SUBJECTS.alice,
    });
    const config = await configFor(issuer, "cail:workbench");
    await expect(
      verifyIdentityJwt(token, config),
    ).resolves.toBeNull();
  });
});
