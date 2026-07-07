# `@cuny-ai-lab/cail-identity`

The CAIL identity-JWT verifier — one pure, load-bearing primitive. It verifies
the gateway-signed CAIL identity JWT (HS256) and returns a normalized identity,
or `null` on **any** failure.

Pure Web Crypto only (`crypto.subtle`, `TextEncoder`, `atob`): the same source
runs unchanged in **Cloudflare Workers** and **Node ≥20**. The public surface is
`string`/`number`/plain-object only — no ambient Cloudflare types leak out.

This package replaces the hand-copied verifier that had drifted across five
repos. The 10 invariants below **are the semver contract**: loosening or
removing any one is a major bump every consumer opts into deliberately.

## Install

Published to GitHub Packages (org-scoped registry). Consumers add an `.npmrc`:

```ini
# .npmrc
@cuny-ai-lab:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

```bash
npm install @cuny-ai-lab/cail-identity
```

## Usage

```ts
import {
  verifyIdentityJwt,
  CAIL_CANONICAL_ISSUER,
  type CailIdentity,
} from "@cuny-ai-lab/cail-identity";

const identity = await verifyIdentityJwt(token, env.CAIL_IDENTITY_JWT_SECRET, {
  // REQUIRED to accept anything — an unconfigured allowlist rejects all tokens.
  allowedIssuers: [CAIL_CANONICAL_ISSUER],
});
if (!identity) {
  // fail closed — 401. Never inspect WHY: there is no failure-reason oracle.
  return new Response("Unauthorized", { status: 401 });
}
// identity.subject is the stable pseudonymous CAIL subject — key all user
// data (budgets, workspaces, audit) by it, never by email.
```

### Signature

```ts
verifyIdentityJwt(
  token: string,
  secret: string,
  opts?: {
    now?: number;
    clockToleranceSeconds?: number;
    allowedIssuers?: string[];
  },
): Promise<CailIdentity | null>

type CailIdentity = {
  subject: string;
  email?: string;
  name?: string;
  entitlements: string[];
};

// Convenience constants for composing your allowlist:
export const CAIL_CANONICAL_ISSUER = "https://tools.ailab.gc.cuny.edu/cail-sso";
export const CAIL_STAGING_ISSUER = "https://tools.cuny.qzz.io/cail-sso";
```

- `secret` is a **function argument** — never stored, never logged. The package
  carries logic only and is safe to publish publicly. Inject it at runtime
  (`CAIL_IDENTITY_JWT_SECRET`).
- `now` defaults to `Math.floor(Date.now() / 1000)`; inject a fixed clock in
  tests or deterministic consumers.
- `clockToleranceSeconds` defaults to **60**. See the clock-tolerance note below.
- `allowedIssuers` is an **exact-match** issuer allowlist (I8). It is **required
  to accept anything**: absent or empty rejects every token (fail closed).
  Compose it from the exported constants — accept prod only:
  `{ allowedIssuers: [CAIL_CANONICAL_ISSUER] }`; accept prod + staging:
  `{ allowedIssuers: [CAIL_CANONICAL_ISSUER, CAIL_STAGING_ISSUER] }`.

## The contract (10 invariants)

Accept **iff all 10 hold**, else return `null` — never throw, never distinguish
which check failed.

| # | Invariant | Rejects when |
|---|-----------|--------------|
| I1 | Structure | `token.split(".")` ≠ 3 parts |
| I2 | Encoding | any segment is not valid base64url |
| I3 | JSON | header or payload is not a JSON **object** |
| I4 | **Alg pinned** | `header.alg !== "HS256"` — the algorithm is hard-coded; the token never chooses it (`none` / `HS384` / `RS256` / HS-confusion all rejected) |
| I5 | **Signature** | `HMAC-SHA256("<headerB64>.<payloadB64>", secret) !== signature` (constant-time via `crypto.subtle.verify`) |
| I6 | **exp required** | `typeof exp !== "number"` OR `exp <= now - tol` |
| I7 | **aud** | `aud !== "cail-internal"` (exact) |
| I8 | **iss exact allowlist** | `typeof iss !== "string"` OR `iss` is not an exact member of `opts.allowedIssuers` — **exact match against a configured set**, not suffix and not substring. Absent/empty `allowedIssuers` rejects ALL tokens (fail closed). Staging is accepted only by being *listed*. (Supersedes the old `endsWith("/cail-sso")`, which accepted `https://evil.example/cail-sso`.) |
| I9 | **nbf if present** | `nbf` present AND (`typeof nbf !== "number"` OR `nbf > now + tol`). Absent `nbf` is allowed. |
| I10 | **sub** | `typeof sub !== "string"` OR `sub === ""` |

**Output mapping (on accept):** `subject = sub`; `email` / `name` are passed
through only if they are strings, else `undefined`; `entitlements` is the array
filtered to strings, defaulting to `[]`. Unknown claims are dropped. The input
is never mutated.

**Invariants that are the whole point:** fail closed on any ambiguity (including
an unconfigured issuer allowlist); no algorithm agility (HS256 pinned in code);
exact-match `iss` and `aud` — trust only the issuers you explicitly list;
verify-only — identity comes only from a validly-signed token, never from
`X-CAIL-*` headers.

## Clock tolerance

`clockToleranceSeconds` (default **60**) is symmetric leeway on `exp` and `nbf`,
the RFC 7519 §4.1 "leeway" case for verification across independently-NTP'd
hosts (60s is the OIDC norm; the JWT is a short-lived session-derived
credential, so the security cost of 60s is negligible).

- `exp` rejects only when `exp <= now - tol` — a token is valid **through**
  `exp + tol`.
- `nbf` rejects only when `nbf > now + tol`.
- `clockToleranceSeconds: 0` restores the strict RFC boundary
  (`exp <= now` rejects, `nbf > now` rejects). Strict is one argument away.

## Development

```bash
npm install
npm run typecheck   # tsc: build config (no ambient node types) + test config
npm run build       # emit dist/ (JS + .d.ts)
npm test            # vitest — the §5 vector table IS the contract
```

Tests mint the valid tokens with [`jose`](https://github.com/panva/jose) (an
independent, audited signer — never our own signer verifying our own output)
and hand-craft the malformed fixtures. A dependency-free **reference reader** in
`test/fixtures.ts` re-derives accept/reject from the raw claims and the I1–I10
rules, so the suite is not merely asserting against the implementation it tests.

## Scope

**In (v1):** this verifier + its result type. **Out:** the origin check, the
CAIL error envelope, the subject-HMAC derivation (minted by the gateway; the
verifier only *reads* the derived `sub`), and any transport/framework glue.
