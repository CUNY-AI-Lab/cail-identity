# @cuny-ai-lab/cail-identity

Verify the RS256 CAIL identity JWT. Hand the verifier the gateway-signed
`X-CAIL-Identity-JWT`, a public JWKS, and the service audience; receive the
normalized CAIL identity or `null` on any failure.

This package is the authentication boundary for the CAIL fleet. Signature and
registered-claim verification are delegated to
[`jose`](https://github.com/panva/jose), which runs on Web Crypto across
Cloudflare Workers, browsers, Bun, and Node 20 or later. CAIL adds canonical
base64url, fatal UTF-8, own-property claims, an RS256 algorithm pin, exact
issuer policy, strict audience shapes, deterministic key selection, and a
fail-closed `null` result.

The package contains no secret. The gateway alone holds the RSA private key;
consumers receive only the public JWKS.

## Install

```bash
bun add github:CUNY-AI-Lab/cail-identity
```

Pin a reviewed commit for reproducibility.

## Usage

```ts
import {
  verifyIdentityJwtV2,
  CAIL_CANONICAL_ISSUER,
} from "@cuny-ai-lab/cail-identity";

const identity = await verifyIdentityJwtV2(token, publicJwks, {
  expectedAudience: "cail:my-service",
  allowedIssuers: [CAIL_CANONICAL_ISSUER],
});

if (!identity) return new Response("Unauthorized", { status: 401 });
```

```ts
verifyIdentityJwtV2(
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

The token must have exactly three canonical base64url segments, a protected
`alg` of `RS256`, a nonempty `kid`, exactly one matching public RSA verification
key, an exact allowed issuer, the expected service audience, finite `exp`, an
optional finite `nbf`, and a nonempty `sub`. Any `crit` member rejects. Audience
arrays must be nonempty, duplicate-free string arrays containing the expected
audience. Unknown claims are dropped; malformed entitlement entries can only
reduce privileges.

Signing-key rotation publishes old and new public keys under distinct `kid`
values. Reusing a `kid` while both keys are present is ambiguous and rejects.

## Development

```bash
bun install
bun run typecheck
bun run build
bun run test
```

Build output is committed so pinned git dependencies install without a build
step.

## Scope

This package verifies identity. It does not fetch JWKS, derive subjects, manage
sessions, enforce origin/CSRF policy, or transport credentials.

## License

MIT — see [LICENSE](LICENSE).
