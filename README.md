# @cuny-ai-lab/cail-identity

Verify the gateway-signed RS256 CAIL identity JWT from
`X-CAIL-Identity-JWT`. The verifier takes a trusted in-memory public JWKS and
the service audience, then returns a fixed identity shape or `null`.

Use this package at the CAIL fleet's authentication boundary. Signature and
registered-claim verification are delegated to
[`jose`](https://github.com/panva/jose), which runs on Web Crypto across
Cloudflare Workers, browsers, Bun, and Node 20 or later. CAIL adds canonical
base64url, fatal UTF-8, own-property claims, an RS256 algorithm pin, exact
issuer comparison, constrained audience shapes, deterministic key selection,
and a fail-closed `null` result.

Consumers give the package a public JWKS. The RSA private key remains at the
gateway and never enters the package.

## Install

```bash
bun add github:CUNY-AI-Lab/cail-identity
```

Pin a reviewed commit for reproducibility.

## Usage

```ts
import {
  verifyIdentityJwt,
  CAIL_CANONICAL_ISSUER,
} from "@cuny-ai-lab/cail-identity";

const identity = await verifyIdentityJwt(token, publicJwks, {
  expectedAudience: "cail:my-service",
  allowedIssuers: [CAIL_CANONICAL_ISSUER],
});

if (!identity) return new Response("Unauthorized", { status: 401 });
```

```ts
verifyIdentityJwt(
  token: string,
  jwks: { keys: JWK[] },
  opts: {
    expectedAudience: string;
    allowedIssuers: string[];
    clockToleranceSeconds?: number;
    now?: number;
  },
): Promise<CailIdentity | null>

type CailIdentity = {
  subject: string;
  email?: string;
  name?: string;
  entitlements: string[];
};
```

## Verification contract

The token must have exactly three canonical base64url segments. Its protected
header must contain `alg: "RS256"` and a nonempty string `kid`. Any `crit`
member rejects, including an empty array. Token-supplied key lookup headers
such as `jku` and `x5u` are never followed.

Key selection considers public RSA keys with the same `kid`, usable RS256
metadata, canonical `n` and `e`, and no private RSA parameters. Verification
continues only when exactly one eligible key remains. Ineligible entries are
ignored, even when they reuse the same `kid`; callers that require every JWKS
`kid` to be globally unique must validate that before calling the verifier.
`jose` and Web Crypto enforce the RS256 signature and RSA key requirements.

`allowedIssuers` must contain exactly one nonempty issuer. `iss` is compared
with that value as a case-sensitive string; there is no prefix, suffix, host,
or URL normalization. Empty or multiple-issuer configuration returns `null`,
which keeps production and staging identity namespaces from being combined.

`aud` must be a nonempty scalar string exactly equal to `expectedAudience`.
Array-valued audiences return `null`, including a one-element array or an array
that contains the expected value.

Time validation requires a finite `exp`. A finite `nbf` is allowed and checked
when present. Both checks use a symmetric 60-second clock tolerance by default.
A present `iat` must be numeric, but the verifier does not require `iat` or use
it to limit token age. A future numeric `iat` is accepted. The verifier also
does not enforce `jti` replay protection or pin a `typ` value.

`sub` must be a nonempty string and is returned verbatim as `subject`. The
verifier does not trim, case-fold, Unicode-normalize, or validate a CAIL subject
format. Treat it as an opaque identifier and never substitute email as a data
key.

`email` and `name` are returned only when they are strings. For `entitlements`,
the verifier preserves every string in order and drops nonstrings; it does not
trim, deduplicate, reject empty strings, or apply an authorization allowlist.
Compare entitlement values exactly, and make authorization decisions against a
service-owned allowlist. Unknown claims are omitted from the result.

## JWKS loading and rotation

The verifier performs no network access, caching, refresh, or retry. It checks
only the JWKS snapshot supplied for that call. A malformed set, an unknown
`kid`, no eligible matching key, multiple eligible matching keys, an import
error, or a bad signature returns `null`.

Prefer a JWKS delivered as trusted deployment configuration. If a consumer
fetches it remotely, that consumer owns the HTTPS origin allowlist, response
size and schema limits, cache lifetime, atomic refresh, and startup behavior.
Never choose a JWKS URL from the token. Decide explicitly whether the consumer
rejects all requests after a refresh failure or temporarily retains a
last-known-good set. Retaining it also extends acceptance of a key that may
have been revoked.

Rotate by publishing old and new public keys under distinct `kid` values,
deploying the overlap, switching the signer, and removing the old key only
after old tokens and clock tolerance have expired. An unknown new `kid` does
not trigger a refresh inside this package.

## Failure, privacy, and deployment boundaries

Every malformed input, verification failure, configuration error, hostile
getter, and unexpected exception resolves to `null`. The package intentionally
does not reveal a failure reason. Return a generic authentication failure and
do not log the JWT, JWKS, email, name, or entitlements.

The verifier does not limit token size or claim count. It also does not limit
the size of an in-memory JWKS. Enforce request and header limits at the trusted
ingress, and bound any remotely loaded JWKS before passing it in.

Browser bundling supports local verification only. Enforce access to server
data and operations in a trusted Worker or server boundary.

## Development

```bash
bun install
bun run typecheck
bun run test
bun run check:dist
bun audit
```

Build output is committed so pinned git dependencies install without a build
step. The suite tests both `src` and the package entry backed by `dist`.
`check:dist` rebuilds the package and fails in CI if the committed output does
not match source.

## Scope

The package handles signed identity validation. Callers remain responsible for
JWKS fetching, subject derivation or canonicalization, sessions, replay policy,
entitlement authorization, tenant isolation, quotas, origin/CSRF policy, and
credential transport.

## License

MIT. See [LICENSE](LICENSE).
