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
Pin an exact published release, then run `bun install` with
`NODE_AUTH_TOKEN` set to a
[classic GitHub PAT](https://docs.github.com/en/packages/learn-github-packages/introduction-to-github-packages#authenticating-to-github-packages)
that has `read:packages`. CI may supply the same environment variable from a
secret. Maintainers keep the same registry and authentication configuration
outside the repository, set `NPM_CONFIG_TOKEN` to a classic PAT with
`write:packages`, verify with `bun publish --dry-run`, and release with
`bun publish`. GitHub Actions may instead use its repository `GITHUB_TOKEN`
with `packages: write`.

## Auth and SSO failure envelope

The package exports the strict auth boundary used by Doorway and browser-facing
Workers. Its only JSON shape is:

```json
{
  "error": {
    "code": "authentication_required",
    "message": "Sign in to continue.",
    "launch": "/launch/agent-studio"
  }
}
```

The finite codes are `authentication_required`, `authentication_failed`,
`invalid_credential`, `session_invalid`, `admission_required`,
`admission_unavailable`, `identity_unavailable`, and
`identity_verification_misconfigured`. `launch` is optional. When present it
must be a root-relative path or a path on
`https://tools.ailab.gc.cuny.edu`; query strings, fragments, dot segments,
backslashes, protocol-relative values, and other origins are rejected.

```ts
import {
  createCailAuthError,
  parseCailAuthErrorJson,
  serializeCailAuthError,
} from "@cuny-ai-lab/cail-identity";

const body = createCailAuthError(
  "authentication_required",
  "Sign in to continue.",
  "/launch/agent-studio",
);
const json = serializeCailAuthError(body);
const parsed = parseCailAuthErrorJson(json); // null for malformed/legacy body
```

The parser rejects flat `{ "error": "..." }` responses and every unknown or
extra field. Consumers continue to own HTTP status, cache headers, browser
redirect timing, and response construction; they should migrate their auth
surfaces to this package's nested body before pinning the release. The package
does not provide session, redirect, or provider policy behavior. The machine-
readable contract is exported as
`@cuny-ai-lab/cail-identity/contract/auth-error-envelope-v1.json`.

## Stable subject

```ts
import { deriveCailSubject } from "@cuny-ai-lab/cail-identity";

const subject = await deriveCailSubject({
  issuer: CUNY_OIDC_ISSUER,
  oidcSubject: trustedUserInfo.sub,
  subjectSalt: CAIL_SUBJECT_SALT,
});
```

The v2 algorithm is:

1. Trim ASCII edge whitespace and uppercase ASCII letters in the trusted OIDC
   subject.
2. Remove one trailing `@LOGIN.CUNY.EDU` realm.
3. Frame the issuer and canonical subject injectively as
   `cail-identity/ownership-subject:v2:` followed by each value's UTF-8 byte
   length and value.
4. Compute `HMAC-SHA256(subjectSalt, framedMaterial)`.
5. Return `cail-` followed by the first 32 lowercase hexadecimal characters.

This function does not authenticate its input. Call it only with a subject
obtained from a verified CUNY token or trusted user-info response. The salt is a
server secret containing at least 32 UTF-8 bytes. The salt and all options are
read once, and the exact validated salt bytes are passed to Web Crypto; the
issuer namespaces otherwise identical subjects. Inputs that canonicalize to
empty or retain an ASCII control
character are rejected; the Lua and TypeScript output vectors cover the
accepted production CUNY shapes.

The v2 framing intentionally changes every derived user ownership ID from the
delimiter-based v1 result. The package contains no migration, aliasing,
backfill, or dual-read behavior. Doorway is the current trusted derivation
boundary and uses this package's v2 algorithm for CUNY sign-in and its private
subject-derivation entrypoint. Other stores and consumers must reconcile their
own persisted ownership data before changing derivation inputs or salts. The
language-neutral `contract/subject-derivation-v2.json` vectors and adjacent Lua
reference support independent implementations without assigning derivation to
the Gateway.

## Stable app-principal subject (ADR-0007)

```ts
import { deriveAppSubject, isAppSubject } from "@cuny-ai-lab/cail-identity";

const appSubject = await deriveAppSubject(appControlPlaneId, APP_SUBJECT_SALT);
```

Headless apps with their own spend partition get `app-` + the first 32
lowercase hexadecimal characters of `HMAC-SHA256(subjectSalt, "app|" + appId)`
— the same construction as the user subject, namespaced by the `app|`
domain-separation prefix. The disjoint `app-` output prefix
(`isAppSubject`) means an app subject can never collide
with a user `cail-` subject in a spend partition, audit row, or workspace key.
The app id is a stable control-plane identifier used byte-exact (no
canonicalization) and must come from a trusted issuing service, never from
user-controlled request data. Its salt has the same 32-UTF-8-byte minimum as
the user-subject derivation salt.

## Signed identity

```ts
import {
  CAIL_CANONICAL_ISSUER,
  loadIdentityVerifierConfig,
  verifyIdentityJwt,
} from "@cuny-ai-lab/cail-identity";

const loaded = await loadIdentityVerifierConfig({
  jwks: env.CAIL_IDENTITY_JWKS,
  issuer: env.CAIL_IDENTITY_ISSUER,
  expectedAudience: "cail:agent-studio",
  supportedIssuers: [CAIL_CANONICAL_ISSUER],
});
if (!loaded.ok) return new Response("Service Unavailable", { status: 503 });

const identity = await verifyIdentityJwt(token, loaded.config);
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
dedicated salt and the injective
`cail-identity/operational-subject:v2` input domain. It is not a reversible
prefix change from `subject`. Services that did not receive this claim omit
subject-bearing operational events rather than inventing a conversion.

In the TypeScript declaration `subject` remains `string`, but runtime
verification requires the exact pattern `^cail-[0-9a-f]{32}$`.

## Verification contract

Call `loadIdentityVerifierConfig` before invoking the verifier. The loader
reads each input option once and returns either a frozen verifier snapshot or
a typed operator-error reason. It requires one canonical HTTPS issuer, one
non-whitespace scalar audience, finite representable test time when supplied,
clock tolerance from 0 through 300 seconds, and a nonempty JWKS. The default
issuer authority contains only the canonical standalone Doorway issuer;
callers may supply an exact canonical authority list.

Every JWKS key must be an eligible public RSA RS256 signing key with canonical
Base64urlUInt `n` and `e`, a nonempty `kid`, and no private material. The
modulus must be an odd integer of at least 2048 bits. The exponent must be an
odd integer from 3 through JavaScript's maximum safe integer; the normal
`65537` exponent is accepted. These eligibility checks run before Web Crypto
key import because import alone does not enforce them. Kids must be globally
distinct. JWKS input is parsed from JSON so key fields have own-data semantics,
then frozen and imported before the snapshot is returned. The verifier never
follows `jku`, `x5u`, or any other token-controlled URL. Signature and
registered-claim verification use
[`jose`](https://github.com/panva/jose).

With a valid snapshot, the verifier accepts a canonical three-part JWT with
`alg: "RS256"`, a known nonempty `kid`, finite `exp`, optional finite `nbf`,
the exact scalar audience and issuer, and a canonical CAIL subject. Invalid
tokens resolve to `null` without exposing a failure oracle. Passing a
forged/non-loader config throws a configuration error.
The verifier performs no network access, JWKS refresh, logging, or token
minting.

Callers own bounded JWKS loading and rotation. Publish old and new public keys
under distinct `kid` values during an overlap, switch the signer, then remove
the old key after issued tokens and clock tolerance have expired.

The exact `aud: "cail:gateway"` identity leg uses this same identity-only
shape. Model access and accounting policy are owned by Registry/Gateway after
verification; this package does not parse or return signed policy claims.

## Config errors are not token errors

The loader validates audience and timing along with the issuer and JWKS. A
token that fails against a successfully loaded snapshot is a client error
(`verifyIdentityJwt` → `null` → 401). A service that cannot load its config is
an operator error the caller must surface as 503 with a structured log, or a
misconfiguration presents as every user's auth silently failing.

```ts
import { loadIdentityVerifierConfig } from "@cuny-ai-lab/cail-identity";

const loaded = await loadIdentityVerifierConfig({
  jwks: env.CAIL_IDENTITY_JWKS,
  issuer: env.CAIL_IDENTITY_ISSUER,
  expectedAudience: "cail:agent-studio",
  supportedIssuers: [CAIL_CANONICAL_ISSUER], // optional
});
if (!loaded.ok) {
  // Includes JWKS, issuer, audience, and timing config-error reasons.
  return new Response("Service Unavailable", { status: 503 });
}
const identity = await verifyIdentityJwt(token, loaded.config);
```

The loader returns config-invalid as a value and does not throw for invalid
caller input. Empty JWKS, empty objects, duplicate kids, private keys, and structurally
ineligible keys are configuration failures. Per-token unknown kids and bad
signatures remain token failures.

## Platform role

CAIL applications verify incoming identity JWTs at their own trusted boundary.
Every JWT has one scalar audience and an app-audience token must not be relayed
to another service. A keyring's `cail:gateway` leg may be forwarded verbatim to
CAIL Model API only after `verifyKeyringGatewayJwt` verifies its signature,
claims, and same-subject invariant. Registry/Gateway then applies model-access
and accounting policy to the verified subject; this package does not provide
that policy.

Subject derivation (`deriveCailSubject`) exists for the trusted authentication
boundary only. Doorway derives the canonical subject from verified CUNY OIDC
input and mints audience-bound identity JWTs. Application code, including the
Gateway, does not derive a person from provider input; it consumes the
canonical subject only after verifying the appropriate identity or Registry
boundary. `contract/subject-derivation-v2.json` and its adjacent Lua reference
provide common vectors for any separately reviewed non-TypeScript producer.

This package does not provide sessions, CAIL API keys, model routing, quotas,
or custom error handling.

## Identity keyring transport (`contract/identity-keyring-v1.json`)

A signed-in person may need more than one audience-bound token: one for the
application they are using, and one for CAIL Model API when that application
acts on their behalf. Forwarding the application's own token to the gateway is
the token-passthrough anti-pattern and fails exact-audience verification by
design. The keyring is the sanctioned alternative: the issuing doorway mints
every leg in one sign-in event and delivers them as two headers, one compact
JWS each.

- `x-cail-identity-jwt` — the token addressed to the receiving application's
  own audience.
- `x-cail-gateway-identity-jwt` —
  optional; the same person's `cail:gateway`-audience token, forwarded
  verbatim to CAIL Model API and never read as authority by the application.

`readIdentityKeyring(headers)` is transport parsing only and fails the whole
keyring closed on any present-but-malformed leg. Before storing or forwarding
the gateway leg, applications MUST call `verifyKeyringGatewayJwt(keyring,
gatewayConfig, verifiedAppSubject)` — full verification against a
`cail:gateway`-audience config plus the invariant that both legs name the
same person. A keyring never weakens each service's own verification: every
receiver still verifies its own leg with `verifyIdentityJwt`.

## Test fixtures (`@cuny-ai-lab/cail-identity/testing`)

Consumers used to invent structurally invalid subjects in tests
(`cail-abc123`, `user:${email}`), which broke when canonical-subject
enforcement arrived. Build fixtures from the blessed subpath instead:

```ts
import {
  loadIdentityVerifierConfig,
  verifyIdentityJwt,
} from "@cuny-ai-lab/cail-identity";
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
const loaded = await loadIdentityVerifierConfig({
  jwks: issuer.jwksJson,
  issuer: issuer.issuer,
  expectedAudience: "cail:agent-studio",
});
if (!loaded.ok) throw new Error(loaded.reason);
const identity = await verifyIdentityJwt(jwt, loaded.config);
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

// Gateway legs are ordinary claimless identity JWTs.
await issuer.mintIdentityJwt({
  audience: "cail:gateway",
});

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
bun run verify
bun audit
```

`bun run verify` first runs the vendored full generic
[anti-slop](https://github.com/dmmulroy/anti-slop) profile, then builds the
package, runs the TypeScript and standalone LuaJIT derivation tests, and checks
the package contents. Resolve lint findings at the parsing or contract
boundary; do not suppress them, hide them behind generic wrappers, or add a
`SAFETY` comment unless it names the runtime invariant established immediately
before the assertion. The vendored source and upstream commit are recorded in
[`tools/oxlint/anti-slop/UPSTREAM.md`](tools/oxlint/anti-slop/UPSTREAM.md).

`bun run check` runs the package checks without linting. The build output ships
in the published package, so consumers install without a build step.
Publishing a stable (non-prerelease) GitHub release whose tag matches `v` plus
the package version publishes that release source to GitHub Packages with the
repository's workflow token. Package publication does not update a production
deployment.

## License

MIT. See [LICENSE](LICENSE).
