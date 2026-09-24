import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  deriveCailSubject,
  isCailPrincipalSubject,
  loadIdentityVerifierConfig,
  verifyIdentityJwt,
} from "@cuny-ai-lab/cail-identity";
import {
  canonicalTestSubject,
  createTestIdentityIssuer,
} from "@cuny-ai-lab/cail-identity/testing";

for (const name of [
  "principal-v1",
  "identity-jwt-claims-v1",
  "auth-error-envelope-v1",
  "subject-derivation-v2",
]) {
  const contract = JSON.parse(
    await readFile(
      new URL(
        import.meta.resolve(`@cuny-ai-lab/cail-identity/contract/${name}.json`),
      ),
      "utf8",
    ),
  );
  assert.ok(Object.keys(contract).length > 0);
}
assert.ok(
  (
    await readFile(
      new URL(
        import.meta.resolve(
          "@cuny-ai-lab/cail-identity/contract/subject-derivation-v2.lua",
        ),
      ),
      "utf8",
    )
  ).length > 0,
);

const subject = await deriveCailSubject({
  issuer: "https://issuer.example.edu",
  oidcSubject: "packed-consumer",
  subjectSalt: "packed-consumer-test-salt-32-bytes-long",
});
assert.equal(isCailPrincipalSubject(subject), true);
const issuer = await createTestIdentityIssuer();
const loaded = await loadIdentityVerifierConfig({
  issuer: issuer.issuer,
  jwks: issuer.jwksJson,
  expectedAudience: "cail:packed-consumer",
});
assert.equal(loaded.ok, true);
const owner = canonicalTestSubject("packed-consumer");
const valid = await issuer.mintIdentityJwt({
  subject: owner,
  audience: "cail:packed-consumer",
});
assert.equal((await verifyIdentityJwt(valid, loaded.config))?.subject, owner);
const wrongAudience = await issuer.mintIdentityJwt({
  subject: owner,
  audience: "cail:another-consumer",
});
assert.equal(await verifyIdentityJwt(wrongAudience, loaded.config), null);
console.log(
  `Installed package exports and JWT verification passed on ${process.version}`,
);
