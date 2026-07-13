# @cuny-ai-lab/cail-identity

Verify the CAIL identity JWT. Hand a verifier the gateway-signed
`X-CAIL-Identity-JWT` and its verification key material, get back the CAIL
subject — or `null` on any failure. Nothing else.

This is the **authentication boundary** for the CAIL fleet — one versioned
implementation, with the whole claim set defined and tested in a single place,
so every service verifies identity the same way.

JWT signature and registered-claim verification are delegated to the
zero-dependency [`jose`](https://github.com/panva/jose) library, which runs on
Web Crypto across **Cloudflare Workers**, browsers, Bun, and **Node ≥20**. CAIL
adds only its stricter profiles: canonical base64url, fatal UTF-8, own-property
claims, pinned algorithms, exact issuer policy, strict audience shapes, and
fail-closed `null`. V1 accepts HS256 with a shared secret. The additive V2
verifier accepts RS256 with an in-memory public JWKS and supports key rotation.
Key material is passed as a function argument and never stored; the package is
logic only and safe to be public.

## Who needs this

Any service that *receives* an `X-CAIL-Identity-JWT` and needs to trust it —
the model proxy, the key service, and any tool that keys its own data
(workspaces, ownership, budgets) by the CAIL subject. If you only *call* the
proxy and never verify a token (a browser frontend, a deployed project), you
want [`@cuny-ai-lab/cail-client`](https://github.com/CUNY-AI-Lab/cail-client)
instead, not this.

## Install

Consumed as a public git dependency. The package commits its build output, so
it resolves with no build step:

```bash
bun add github:CUNY-AI-Lab/cail-identity
# or
npm install github:CUNY-AI-Lab/cail-identity
```

Pin to a tag or commit for reproducibility, e.g.
`github:CUNY-AI-Lab/cail-identity#v1.0.0`.

> Not on GitHub Packages: that registry can't host public packages and needs a
> `write:packages` token to publish. The public git-dep above is the supported
> path.

### Upgrade note: 32-byte secret minimum

Current releases reject every token when `CAIL_IDENTITY_JWT_SECRET` is shorter
than 32 UTF-8 bytes. Before pinning a hardened commit, confirm that the producer
and every verifier use the same secret and that it meets this minimum. For new
coordinated provisioning, `openssl rand -hex 32` produces a 64-byte ASCII
secret. Changing only one side invalidates all tokens between them.

## Quick start

### V1: HS256 shared secret

```ts
import {
  verifyIdentityJwt,
  CAIL_CANONICAL_ISSUER,
  CAIL_STAGING_ISSUER,
  type CailIdentity,
} from "@cuny-ai-lab/cail-identity";

const identity = await verifyIdentityJwt(token, env.CAIL_IDENTITY_JWT_SECRET, {
  // Which issuers this service trusts. REQUIRED — an unconfigured allowlist
  // rejects every token. List staging only where you accept staging tokens.
  allowedIssuers: [CAIL_CANONICAL_ISSUER, CAIL_STAGING_ISSUER],
});

if (!identity) {
  // Fail closed. There is no failure-reason oracle — you get `null` or nothing.
  return new Response("Unauthorized", { status: 401 });
}

// identity.subject is the stable pseudonymous CAIL subject. Key ALL user data
// (budgets, workspaces, audit) by it — never by email.
```

### V2: RS256 public JWKS

```ts
import {
  verifyIdentityJwtV2,
  CAIL_CANONICAL_ISSUER,
} from "@cuny-ai-lab/cail-identity";

const identity = await verifyIdentityJwtV2(token, publicJwks, {
  expectedAudience: "cail-internal",
  allowedIssuers: [CAIL_CANONICAL_ISSUER],
});

if (!identity) {
  return new Response("Unauthorized", { status: 401 });
}
```

## Signature

### V1

```ts
verifyIdentityJwt(
  token: string,
  secret: string,
  opts?: {
    allowedIssuers?: string[];      // exact-match set; absent/empty ⇒ reject all
    clockToleranceSeconds?: number; // default 60; 0 = strict RFC boundary
    now?: number;                   // default Math.floor(Date.now()/1000)
  },
): Promise<CailIdentity | null>

type CailIdentity = {
  subject: string;
  email?: string;
  name?: string;
  entitlements: string[];
};

// Convenience constants for composing allowedIssuers:
export const CAIL_CANONICAL_ISSUER = "https://tools.ailab.gc.cuny.edu/cail-sso";
export const CAIL_STAGING_ISSUER   = "https://tools.cuny.qzz.io/cail-sso";
```

- **`secret`** — inject at runtime (`CAIL_IDENTITY_JWT_SECRET`); never hard-code.
  Must be at least **32 UTF-8 bytes** (RFC 7518 §3.2 HS256 minimum key size); a
  shorter secret fails closed — every verification returns `null`. Production
  provisioning (`openssl rand -hex 32` = 64 bytes) clears this comfortably.
- **`allowedIssuers`** — exact-match, not suffix. Absent or empty rejects every
  token (fail closed). Staging is accepted only by being listed.
- **`clockToleranceSeconds`** — symmetric leeway on `exp`/`nbf`, default 60 (see
  below). Pass `0` for the strict boundary.
- **`now`** — inject a fixed clock in tests.

### V2

```ts
verifyIdentityJwtV2(
  token: string,
  jwks: { keys: JWK[] },
  opts: {
    expectedAudience: string;
    allowedIssuers: string[];
    clockToleranceSeconds?: number; // default 60; must be nonnegative
    now?: number;
  },
): Promise<CailIdentity | null>
```

- **`jwks`** — an in-memory public JSON Web Key Set. The token must carry a
  nonempty own `kid`, and the set must contain exactly one matching eligible
  RSA verification key. Distinct `kid` values may overlap during rotation.
- **`expectedAudience`** — required nonempty string. The token `aud` may be the
  exact scalar or a nonempty, duplicate-free string array containing it.
- **`allowedIssuers`** — required nonempty, duplicate-free array of nonempty
  exact issuer strings.
- **`clockToleranceSeconds`** and **`now`** — the same clock controls as V1,
  except V2 rejects negative tolerance.

## V1 contract — 10 invariants

Accept **iff all ten hold**, else return `null`. Never throws; never tells you
which check failed. Loosening or removing any invariant is a **major** semver
bump every consumer opts into.

| # | Invariant | Rejects when |
|---|-----------|--------------|
| I1 | Structure | `token.split(".")` ≠ 3 parts |
| I2 | Encoding | any segment is not valid **canonical** base64url (non-zero trailing padding bits rejected per RFC 4648 §3.5 — the token string is not malleable) |
| I3 | JSON | header or payload is not valid-UTF-8 (fatal decode, RFC 8725 §3.7) JSON parsing to an **object** |
| I4 | **Alg pinned** | `header.alg !== "HS256"` — hard-coded; the token never chooses the algorithm (`none`/`HS384`/`RS256`/HS-confusion all rejected). A header carrying its own `crit` member also rejects (RFC 7515 §4.1.11) |
| I5 | **Signature** | `jose.jwtVerify` rejects unless the HMAC-SHA256 signature over `"<headerB64>.<payloadB64>"` verifies with the supplied secret and the allowed algorithm is exactly `HS256` |
| I6 | **exp required** | `typeof exp !== "number"` OR `exp <= now - tol` |
| I7 | **aud** | `aud !== "cail-internal"` (exact) |
| I8 | **iss allowlist** | `iss` is not an exact member of `allowedIssuers` — exact match, not suffix/substring. Absent/empty allowlist rejects all. |
| I9 | **nbf if present** | `nbf` present AND (`typeof nbf !== "number"` OR `nbf > now + tol`); absent `nbf` allowed |
| I10 | **sub** | `typeof sub !== "string"` OR `sub === ""` |

On accept: `subject = sub`; `email`/`name` pass through only if strings;
`entitlements` is filtered to strings (default `[]`); unknown claims are
dropped; the input is never mutated.

## V2 contract

V2 returns the same `CailIdentity` shape and the same optional-claim behavior as
V1. It accepts only when all of these checks pass:

| Area | Requirement |
|------|-------------|
| Structure | Exactly three nonempty, canonical base64url segments; header and payload are fatal-UTF-8 JSON objects |
| Header | Own `alg` is exactly `RS256`; own `kid` is a nonempty string; any own `crit` rejects |
| Key selection | JWKS has exactly one matching public RSA key eligible for RS256 verification; ambiguous, unknown, malformed, private, encryption-only, or noncanonical key material rejects |
| Signature | `jose.jwtVerify` verifies RSASSA-PKCS1-v1_5 with SHA-256 and the selected key; no other algorithm is allowed |
| Audience | Own `aud` is the expected nonempty scalar, or a unique nonempty string array containing it |
| Claims | Own `iss` exactly matches the configured allowlist; finite `exp` is required; finite `nbf` is checked when present; own `sub` is nonempty |
| Failure | Every malformed, unsupported, unauthorized, or ambiguous input returns `null` without mutation or a reason oracle |

An RSA signing-key rotation publishes old and new public keys together under
different `kid` values. Reusing a `kid` while both keys are present creates an
ambiguous selection and V2 rejects the token.

## Clock tolerance

`clockToleranceSeconds` (default **60**) is symmetric leeway on `exp` and `nbf`
— the RFC 7519 §4.1 leeway case for verifying across independently-NTP'd hosts,
and the OIDC norm. `exp` is valid **through** `exp + tol`; `nbf` rejects only
when `nbf > now + tol`. Pass `0` to restore the strict RFC boundary
(`exp <= now`, `nbf > now`). The security cost of 60s is negligible — the JWT is
a short-lived, session-derived credential.

## Development

```bash
bun install
bun run typecheck   # tsc: build config (clean public surface) + test config
bun run build       # emit dist/ (JS + .d.ts) — committed so git-deps resolve
bun run test        # Vitest; the vector table IS the contract
```

Tests mint valid HS256 and RS256 tokens with `jose` and hand-craft malformed
cases. The V1 suite also uses a dependency-free reference reader to re-derive
accept/reject from raw claims.

The runtime `jose` version is pinned exactly. Verification-library upgrades are
reviewed and committed deliberately rather than entering auth consumers through
an unrelated lockfile refresh.

## Scope

**In:** the V1 HS256 verifier, the V2 RS256/JWKS verifier, and their shared
result type. **Out:** JWKS fetching or caching, the origin/CSRF check, the CAIL
error envelope, subject derivation (the gateway mints `sub`; these only read
it), and any transport or framework glue.

## License

MIT — see [LICENSE](LICENSE).
