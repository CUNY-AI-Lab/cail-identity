# @cuny-ai-lab/cail-identity

Verify the CAIL identity JWT. One small, load-bearing function: hand it the
gateway-signed `X-CAIL-Identity-JWT` and the shared secret, get back the CAIL
subject — or `null` on any failure. Nothing else.

This is the **authentication boundary** for the CAIL fleet. It used to be
hand-copied into every service, and the copies drifted (one skipped `nbf`,
another accepted a token from `evil.example/cail-sso`). Now there's one
implementation, versioned, with the whole claim set audited in one place.

Pure Web Crypto (`crypto.subtle`, `TextEncoder`, `atob`) — the same source runs
unchanged in **Cloudflare Workers** and **Node ≥20**. The secret is a function
argument, never stored; the package is logic only and safe to be public.

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

## Quick start

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

## Signature

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
- **`allowedIssuers`** — exact-match, not suffix. Absent or empty rejects every
  token (fail closed). Staging is accepted only by being listed.
- **`clockToleranceSeconds`** — symmetric leeway on `exp`/`nbf`, default 60 (see
  below). Pass `0` for the strict boundary.
- **`now`** — inject a fixed clock in tests.

## The contract — 10 invariants

Accept **iff all ten hold**, else return `null`. Never throws; never tells you
which check failed. Loosening or removing any invariant is a **major** semver
bump every consumer opts into.

| # | Invariant | Rejects when |
|---|-----------|--------------|
| I1 | Structure | `token.split(".")` ≠ 3 parts |
| I2 | Encoding | any segment is not valid base64url |
| I3 | JSON | header or payload is not a JSON **object** |
| I4 | **Alg pinned** | `header.alg !== "HS256"` — hard-coded; the token never chooses the algorithm (`none`/`HS384`/`RS256`/HS-confusion all rejected) |
| I5 | **Signature** | HMAC-SHA256 over `"<headerB64>.<payloadB64>"` with `secret` ≠ signature (constant-time via `crypto.subtle.verify`) |
| I6 | **exp required** | `typeof exp !== "number"` OR `exp <= now - tol` |
| I7 | **aud** | `aud !== "cail-internal"` (exact) |
| I8 | **iss allowlist** | `iss` is not an exact member of `allowedIssuers` — exact match, not suffix/substring. Absent/empty allowlist rejects all. |
| I9 | **nbf if present** | `nbf` present AND (`typeof nbf !== "number"` OR `nbf > now + tol`); absent `nbf` allowed |
| I10 | **sub** | `typeof sub !== "string"` OR `sub === ""` |

On accept: `subject = sub`; `email`/`name` pass through only if strings;
`entitlements` is filtered to strings (default `[]`); unknown claims are
dropped; the input is never mutated.

## Clock tolerance

`clockToleranceSeconds` (default **60**) is symmetric leeway on `exp` and `nbf`
— the RFC 7519 §4.1 leeway case for verifying across independently-NTP'd hosts,
and the OIDC norm. `exp` is valid **through** `exp + tol`; `nbf` rejects only
when `nbf > now + tol`. Pass `0` to restore the strict RFC boundary
(`exp <= now`, `nbf > now`). The security cost of 60s is negligible — the JWT is
a short-lived, session-derived credential.

## Development

```bash
npm install
npm run typecheck   # tsc: build config (clean public surface) + test config
npm run build       # emit dist/ (JS + .d.ts) — committed so git-deps resolve
npm test            # vitest — the vector table IS the contract
```

Tests mint valid tokens with [`jose`](https://github.com/panva/jose) (an
independent audited signer, never our own signer verifying our own output) and
hand-craft the malformed cases. A dependency-free reference reader re-derives
accept/reject from the raw claims, so the suite validates the contract, not just
the implementation.

## Scope

**In (v1):** this verifier and its result type. **Out:** the origin/CSRF check,
the CAIL error envelope, the subject-HMAC derivation (the gateway mints `sub`;
this only *reads* it), and any transport or framework glue.

## License

MIT — see [LICENSE](LICENSE).
