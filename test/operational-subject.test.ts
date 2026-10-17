import { describe, expect, it } from "vitest";

import {
  deriveCailOperationalSubject,
  deriveCailSubject,
  loadIdentityVerifierConfig,
  verifyIdentityJwt,
} from "../src/index.js";
import {
  TEST_OPERATIONAL_SUBJECTS,
  TEST_SUBJECTS,
  createTestIdentityIssuer,
} from "../src/testing.js";

const NOW = 2_000_000;
const AUDIENCE = "cail:workbench";
const issuer = await createTestIdentityIssuer();
const loaded = await loadIdentityVerifierConfig({
  jwks: issuer.jwksJson,
  issuer: issuer.issuer,
  expectedAudience: AUDIENCE,
  now: NOW,
});
if (!loaded.ok) throw new Error(`fixture config failed: ${loaded.reason}`);
const config = loaded.config;

describe("operational identity pseudonym", () => {
  it("derives a different pseudonym than the ownership subject under the same salt", async () => {
    const input = {
      issuer: "https://issuer.example",
      oidcSubject: "ALICE@login.cuny.edu",
    };
    const salt = "one-salt-for-both-domains-at-least-32-bytes";
    const ownership = await deriveCailSubject({ ...input, subjectSalt: salt });
    const operational = await deriveCailOperationalSubject({
      ...input,
      operationalSubjectSalt: salt,
    });
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
    // SAFETY: the null-prototype object is populated with the exact
    // operational derivation option accessors immediately below.
    const hostile = Object.create(null) as {
      issuer: string;
      oidcSubject: string;
      operationalSubjectSalt: string;
    };
    // SAFETY: Object.keys(valid) contains exactly the three option names used
    // by the accessor map below.
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
    await expect(deriveCailOperationalSubject(hostile)).resolves.toBe(expected);
    expect(reads).toEqual({
      issuer: 1,
      oidcSubject: 1,
      operationalSubjectSalt: 1,
    });
  });

  it("returns a validated optional log_sub claim from a signed token", async () => {
    const token = await issuer.mintIdentityJwt({
      audience: AUDIENCE,
      subject: TEST_SUBJECTS.alice,
      operationalSubject: TEST_OPERATIONAL_SUBJECTS.alice,
      now: NOW,
    });
    await expect(verifyIdentityJwt(token, config)).resolves.toMatchObject({
      subject: TEST_SUBJECTS.alice,
      operationalSubject: TEST_OPERATIONAL_SUBJECTS.alice,
    });
  });

  it("rejects a malformed log_sub claim", async () => {
    const token = await issuer.mintIdentityJwt({
      audience: AUDIENCE,
      operationalSubject: TEST_SUBJECTS.alice,
      now: NOW,
    });
    await expect(verifyIdentityJwt(token, config)).resolves.toBeNull();
  });
});
