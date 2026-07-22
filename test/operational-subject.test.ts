import { describe, expect, it } from "vitest";

import {
  deriveCailOperationalSubject,
  deriveCailSubject,
  isCailOperationalSubject,
  verifyIdentityJwt,
} from "../src/index.js";
import {
  TEST_OPERATIONAL_SUBJECTS,
  TEST_SUBJECTS,
  createTestIdentityIssuer,
} from "../src/testing.js";

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

  it("returns a validated optional log_sub claim from a signed token", async () => {
    const issuer = await createTestIdentityIssuer();
    const token = await issuer.mintIdentityJwt({
      audience: "cail:workbench",
      subject: TEST_SUBJECTS.alice,
      operationalSubject: TEST_OPERATIONAL_SUBJECTS.alice,
    });
    await expect(
      verifyIdentityJwt(token, issuer.jwks, {
        expectedAudience: "cail:workbench",
        allowedIssuers: [issuer.issuer],
      }),
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
    await expect(
      verifyIdentityJwt(token, issuer.jwks, {
        expectedAudience: "cail:workbench",
        allowedIssuers: [issuer.issuer],
      }),
    ).resolves.toBeNull();
  });
});
