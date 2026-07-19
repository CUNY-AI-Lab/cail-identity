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
