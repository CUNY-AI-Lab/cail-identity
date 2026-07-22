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

Configure authentication outside the repository, for example in the user's
`~/.npmrc`:

```ini
//npm.pkg.github.com/:_authToken=${NODE_AUTH_TOKEN}
```

These are registry configuration files that Bun reads; no npm CLI is required.
Pin an exact release, for example `"@cuny-ai-lab/cail-identity": "4.6.0"`, then
run `bun install` with `NODE_AUTH_TOKEN` set to a
[classic GitHub PAT](https://docs.github.com/en/packages/learn-github-packages/introduction-to-github-packages#authenticating-to-github-packages)
that has `read:packages`. CI may supply the same environment variable from a
secret. Maintainers keep the same registry and authentication configuration
outside the repository, set `NODE_AUTH_TOKEN` to a classic PAT with
`write:packages`, verify with `bun publish --dry-run`, and release with
`bun publish`. GitHub Actions may instead use its repository `GITHUB_TOKEN`
with `packages: write`.

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

1. Trim ASCII edge whitespace and uppercase ASCII letters in the trusted OIDC
   subject.
2. Remove one trailing `@LOGIN.CUNY.EDU` realm.
3. Compute `HMAC-SHA256(subjectSalt, issuer + "|" + canonicalSubject)`.
4. Return `cail-` followed by the first 32 lowercase hexadecimal characters.

This function does not authenticate its input. Call it only with a subject
obtained from a verified CUNY token or trusted user-info response. The salt is a
server secret containing at least 32 UTF-8 bytes, matching the gateway's
minimum. The issuer namespaces otherwise identical subjects. Inputs that
canonicalize to empty or retain an ASCII control character are rejected; the
Lua and TypeScript output vectors cover the accepted production CUNY shapes.

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
user-controlled request data. Its salt has the same 32-UTF-8-byte minimum as
the user-subject derivation salt.

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
  operationalSubject?: `cail-v1-${string}`;
  email?: string;
  name?: string;
  entitlements: string[];
};
```

`operationalSubject` comes only from a validated `log_sub` claim. The trusted
identity boundary derives it with `deriveCailOperationalSubject` using a
dedicated salt and the domain-separated operational-log v1 input. It is not a
reversible prefix change from `subject`. Services that did not receive this
claim omit subject-bearing operational events rather than inventing a
conversion.

In the TypeScript declaration `subject` remains `string`, but runtime
verification requires the exact pattern `^cail-[0-9a-f]{32}$`.

## Verification contract

The verifier accepts exactly one configured issuer and one scalar audience. It
requires a canonical three-part JWT, `alg: "RS256"`, a nonempty `kid`, a finite
`exp`, an optional finite `nbf`, and the canonical CAIL subject. Issuer and
audience comparisons are exact and case-sensitive. Clock tolerance defaults to
60 seconds and may be configured from 0 through 300 seconds; larger values fail
closed rather than silently weakening expiration and not-before checks.
Unencoded-payload (`b64: false`) JWTs and critical header extensions are not
part of the identity profile.

The supplied JWKS must contain exactly one eligible public RSA verification key
for the token's `kid`. The verifier never follows `jku`, `x5u`, or any other
token-controlled URL. It rejects private JWK parameters (including symmetric
`k` material) and non-minimal RSA Base64urlUInt encodings before importing the
key. Signature and registered-claim verification use
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

The helper never throws — config-invalid is a returned value. Validation
requires a JWK Set object with a `keys` array of objects containing no private
JWK parameters and a canonical, exact issuer; private parameters make the JWKS
malformed. An empty `keys` array is still a loaded config, and per-`kid` public
RSA key eligibility remains token validation. If `supportedIssuers` is
supplied, it must itself be a unique nonempty array of canonical issuer
strings.

## Platform role

CAIL applications verify incoming identity JWTs at their own trusted boundary.
A gateway JWT has one scalar audience for the service receiving it and must
never be relayed to another service. Model-platform calls use a user-bound CAIL
credential or an approved audience-pinned exchange/facade; only a request sent
directly to the model proxy may carry a JWT whose sole audience is
`cail:model-proxy`. The proxy binds verified subjects and credentials to model
access and spend attribution.

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

`mintIdentityJwt` can also mint well-formed-but-edge-case tokens — signed by
the same real key the kit's JWKS advertises — so verifier negatives don't need
consumer-local signers:

```ts
// auth_time (session-binding contracts, e.g. the gateway keys facade).
await issuer.mintIdentityJwt({ audience: AUD, authTime: now });

// nbf (not-yet-valid negatives).
await issuer.mintIdentityJwt({ audience: AUD, notBefore: now + 3600 });

// Array-valued aud — a shape CAIL verifiers must REJECT.
await issuer.mintIdentityJwt({ audience: [AUD] });

// Arbitrary payload claim overrides: set any claim, or `undefined` to omit.
await issuer.mintIdentityJwt({
  audience: AUD,
  claims: { acr: "custom", exp: undefined },
});
```

The kit signs REAL RS256 tokens only. It will never mint `alg:"none"`,
non-RS256 algorithms, or wrong-key signatures — genuinely malformed shapes
stay consumer-local by design.

## Principal contract

`isCailPrincipalSubject` accepts either a canonical verified user subject
(`cail-<32 lowercase hex>`) or a trusted application accounting subject
(`app-<32 lowercase hex>`). It validates only the identifier shape; it does
not authenticate the caller. The packaged
`@cuny-ai-lab/cail-identity/contract/principal-v1.json` schema is the
language-neutral conformance surface.
The adjacent `contract/identity-jwt-claims-v1.json` schema pins the optional,
separately keyed `log_sub` claim used by operational event producers.

## Development

```bash
bun install
bun run check
bun run check:package
bun audit
bun publish --dry-run
```

Build output is committed and ships in the published package, so consumers
install without a build step.

## License

MIT. See [LICENSE](LICENSE).
