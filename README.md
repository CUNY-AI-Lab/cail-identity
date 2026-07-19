# `@cuny-ai-lab/cail-identity`

The shared stable-subject and signed-identity contract for CAIL applications.
It runs on Web Crypto in Cloudflare Workers, browsers, Bun, and Node 20 or
newer.

The package has two deliberately separate jobs:

1. A trusted CUNY authentication boundary can derive the stable pseudonymous
   `cail-…` subject.
2. CAIL services can verify an RS256 identity JWT containing that subject.

Neither operation trusts request headers or user-supplied identity fields.

## Installation (GitHub Packages)

The package is published to GitHub Packages under the `@cuny-ai-lab` scope.
Add the registry mapping to the consuming repository's `.npmrc` (resolution
only — never commit a token):

```
@cuny-ai-lab:registry=https://npm.pkg.github.com
```

Pin a semver range, for example `"@cuny-ai-lab/cail-identity": "^4.0.0"`, then
run `bun install` with `NODE_AUTH_TOKEN` set in the environment to a GitHub
PAT that has `read:packages` (supplied by a user-level `~/.npmrc` or a CI
secret). Maintainers publish with `npm publish`; `bun publish` does not
authenticate against GitHub Packages.

## Stable subject

```ts
import { deriveCailSubject } from "@cuny-ai-lab/cail-identity";

const subject = await deriveCailSubject({
  issuer: CUNY_OIDC_ISSUER,
  oidcSubject: trustedUserInfo.sub,
  subjectSalt: CAIL_SUBJECT_SALT,
});
```

The established algorithm is:

1. Trim and uppercase the trusted OIDC subject.
2. Remove one trailing `@LOGIN.CUNY.EDU` realm.
3. Compute `HMAC-SHA256(subjectSalt, issuer + "|" + canonicalSubject)`.
4. Return `cail-` followed by the first 32 lowercase hexadecimal characters.

This function does not authenticate its input. Call it only with a subject
obtained from a verified CUNY token or trusted user-info response. The salt is a
server secret. The issuer namespaces otherwise identical subjects.

## Stable app-principal subject (ADR-0007)

```ts
import { deriveAppSubject, isAppSubject } from "@cuny-ai-lab/cail-identity";

const appSubject = await deriveAppSubject(appControlPlaneId, APP_SUBJECT_SALT);
```

Headless apps with their own spend partition get `app-` + the first 32
lowercase hexadecimal characters of `HMAC-SHA256(subjectSalt, "app|" + appId)`
— the same construction as the user subject, namespaced by the `app|`
domain-separation prefix. The disjoint `app-` output prefix
(`APP_SUBJECT_PATTERN`, `isAppSubject`) means an app subject can never collide
with a user `cail-` subject in a spend partition, audit row, or workspace key.
The app id is a stable control-plane identifier used byte-exact (no
canonicalization) and must come from a trusted issuing service, never from
user-controlled request data.

## Signed identity

```ts
import {
  CAIL_CANONICAL_ISSUER,
  verifyIdentityJwt,
} from "@cuny-ai-lab/cail-identity";

const identity = await verifyIdentityJwt(token, publicJwks, {
  expectedAudience: "cail:agent-studio",
  allowedIssuers: [CAIL_CANONICAL_ISSUER],
});

if (!identity) return new Response("Unauthorized", { status: 401 });
```

The result is:

```ts
type CailIdentity = {
  subject: `cail-${string}`;
  email?: string;
  name?: string;
  entitlements: string[];
};
```

In the TypeScript declaration `subject` remains `string`, but runtime
verification requires the exact pattern `^cail-[0-9a-f]{32}$`.

## Verification contract

The verifier accepts exactly one configured issuer and one scalar audience. It
requires a canonical three-part JWT, `alg: "RS256"`, a nonempty `kid`, a finite
`exp`, an optional finite `nbf`, and the canonical CAIL subject. Issuer and
audience comparisons are exact and case-sensitive.

The supplied JWKS must contain exactly one eligible public RSA verification key
for the token's `kid`. The verifier never follows `jku`, `x5u`, or any other
token-controlled URL. Signature and registered-claim verification use
[`jose`](https://github.com/panva/jose).

Every malformed input, verification failure, configuration error, or
unexpected exception resolves to `null`. The verifier does not expose a
failure oracle and performs no network access, JWKS refresh, logging, or token
minting.

Callers own bounded JWKS loading and rotation. Publish old and new public keys
under distinct `kid` values during an overlap, switch the signer, then remove
the old key after issued tokens and clock tolerance have expired.

## Config errors are not token errors

`parseIdentityConfig` owns the other side of that boundary: loading the
verification config itself. A token that fails against a successfully loaded
JWKS is a client error (`verifyIdentityJwt` → `null` → 401). A service that
cannot load or parse its own config — unset or malformed `CAIL_IDENTITY_JWKS`,
missing or unsupported issuer — is an operator error the caller must surface
as 503 with a structured log, or a misconfiguration presents as every user's
auth silently failing.

```ts
import { parseIdentityConfig } from "@cuny-ai-lab/cail-identity";

const config = parseIdentityConfig({
  jwks: env.CAIL_IDENTITY_JWKS,
  issuer: env.CAIL_IDENTITY_ISSUER,
  supportedIssuers: [CAIL_CANONICAL_ISSUER, CAIL_STAGING_ISSUER], // optional
});
if (!config.ok) {
  // config.reason: "jwks_missing" | "jwks_malformed" | "issuer_missing" | "issuer_unsupported"
  return new Response("Service Unavailable", { status: 503 });
}
const identity = await verifyIdentityJwt(token, config.jwks, {
  expectedAudience: "cail:agent-studio",
  allowedIssuers: [config.issuer],
});
```

The helper never throws — config-invalid is a returned value. Validation is
structural (a JWK Set object with a `keys` array of objects); an empty `keys`
array is a loaded config, and per-`kid` key selection remains token
validation.

## Platform role

CAIL applications verify incoming identity JWTs at their own trusted boundary.
When they call the model platform, they give the same audience-appropriate JWT
to `@cuny-ai-lab/cail-client`. The CAIL model proxy performs this verification
and binds the token's stable subject to model access, spend, and quotas.

Subject derivation (`deriveCailSubject`) exists for the trusted authentication
boundary only — the SSO gate and its verification tooling. Application code
never derives subjects; it receives them inside verified tokens. The gate's
Lua implementation (`gateway/lua/cail/identity.lua` in the cail-gateway repo)
must stay in lockstep with this package; the vectors in `test/subject.test.ts`
are the shared contract.

This package does not provide sessions, CAIL API keys, model routing, quotas,
or custom error handling.

## Test fixtures (`@cuny-ai-lab/cail-identity/testing`)

Consumers used to invent structurally invalid subjects in tests
(`cail-abc123`, `user:${email}`), which broke when canonical-subject
enforcement arrived. Build fixtures from the blessed subpath instead:

```ts
import {
  TEST_SUBJECTS,
  canonicalTestSubject,
  createTestIdentityIssuer,
} from "@cuny-ai-lab/cail-identity/testing";

// Deterministic canonical subjects — no hand-maintained hex literals.
const owner = canonicalTestSubject("owner");          // cail-<32 lowercase hex>
const other = TEST_SUBJECTS.bob;                      // ready-made, distinct

// An in-memory RS256 issuer whose tokens verify via verifyIdentityJwt.
const issuer = await createTestIdentityIssuer();
const jwt = await issuer.mintIdentityJwt({
  audience: "cail:agent-studio",
  subject: owner,
  email: "owner@gc.cuny.edu",
});
const identity = await verifyIdentityJwt(jwt, issuer.jwks, {
  expectedAudience: "cail:agent-studio",
  allowedIssuers: [issuer.issuer],
});
```

`canonicalTestSubject(seed)` is `cail-` + the first 32 lowercase hex
characters of SHA-256(seed): deterministic, distinct per seed, and always the
same shape `deriveCailSubject` emits. It is unsalted and test-only — never a
pseudonymization function. The subpath is additive test support: the runtime
entry never imports it, and it imports no test framework.

## Development

```bash
bun install
bun run typecheck
bun run test
bun run check:dist
bun audit
```

Build output is committed and ships in the published package, so consumers
install without a build step.

## License

MIT. See [LICENSE](LICENSE).
