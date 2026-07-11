import { describe, it, expect } from "vitest";
import { verifyIdentityJwt } from "../src/index.js";
import {
  SECRET,
  WRONG_SECRET,
  NOW,
  mintWithJose,
  mintHmacAlg,
  signWithHeaderAlg,
  signRawPayload,
  craftUnsigned,
  tamperPayloadByte,
  b64urlStr,
  referenceAccept,
} from "./fixtures.js";

const ISS = "https://tools.ailab.gc.cuny.edu/cail-sso";
const STAGING_ISS = "https://tools.cuny.qzz.io/cail-sso";
const AUD = "cail-internal";

// Default allowlist for the bulk of the suite (I8): both issuers listed, so
// canonical- and staging-iss happy-path tokens are accepted. Vectors that
// probe the allowlist itself pass their own `allowedIssuers` explicitly.
const DEFAULT_ALLOW = [ISS, STAGING_ISS];

/** Base claim set that PASSES at now=NOW with default tolerance. */
function baseClaims(over: Record<string, unknown> = {}) {
  return {
    sub: "cail-subject-abc",
    aud: AUD,
    iss: ISS,
    exp: NOW + 3600,
    ...over,
  };
}

/**
 * Assert the impl agrees with the reference reader, and return the impl result.
 * `sigValid` tells the reference reader the crypto verdict it can't compute.
 */
async function checkAgainstReference(
  token: string,
  secret: string,
  sigValid: boolean,
  opts?: {
    now?: number;
    clockToleranceSeconds?: number;
    allowedIssuers?: string[];
  },
) {
  const now = opts?.now ?? NOW;
  const tol =
    opts?.clockToleranceSeconds ??
    (opts && "clockToleranceSeconds" in opts ? 0 : 60);
  const allow =
    opts && "allowedIssuers" in opts ? opts.allowedIssuers! : DEFAULT_ALLOW;
  const ref = referenceAccept(token, sigValid, now, tol, allow);
  const got = await verifyIdentityJwt(token, secret, {
    now,
    allowedIssuers: allow,
    ...opts,
  });
  if (ref.accept) {
    expect(got, "impl rejected a token the reference accepted").not.toBeNull();
    expect(got).toEqual(ref.identity);
  } else {
    expect(got, "impl accepted a token the reference rejected").toBeNull();
  }
  return got;
}

// ===========================================================================
// Happy path
// ===========================================================================

describe("happy path", () => {
  it("V1 valid minimal token -> accept, subject==sub, entitlements []", async () => {
    const t = await mintWithJose(baseClaims());
    const got = await checkAgainstReference(t, SECRET, true);
    expect(got).toEqual({
      subject: "cail-subject-abc",
      email: undefined,
      name: undefined,
      entitlements: [],
    });
  });

  it("V2 email/name/entitlements passed through", async () => {
    const t = await mintWithJose(
      baseClaims({
        email: "user@gc.cuny.edu",
        name: "Ada Lovelace",
        entitlements: ["a", "b"],
      }),
    );
    const got = await checkAgainstReference(t, SECRET, true);
    expect(got).toEqual({
      subject: "cail-subject-abc",
      email: "user@gc.cuny.edu",
      name: "Ada Lovelace",
      entitlements: ["a", "b"],
    });
  });

  it("V3 staging iss + allowlist=[canonical, staging] -> accept (I8 exact, listed)", async () => {
    const t = await mintWithJose(baseClaims({ iss: STAGING_ISS }));
    const got = await checkAgainstReference(t, SECRET, true, {
      allowedIssuers: [ISS, STAGING_ISS],
    });
    expect(got?.subject).toBe("cail-subject-abc");
  });

  it("V3b staging iss + allowlist=[canonical] only -> null (accepted only when listed)", async () => {
    const t = await mintWithJose(baseClaims({ iss: STAGING_ISS }));
    expect(
      await verifyIdentityJwt(t, SECRET, { now: NOW, allowedIssuers: [ISS] }),
    ).toBeNull();
    await checkAgainstReference(t, SECRET, true, { allowedIssuers: [ISS] });
  });

  it("V3c canonical iss + allowlist absent -> null (fail closed, loud)", async () => {
    const t = await mintWithJose(baseClaims()); // canonical iss
    // No allowedIssuers at all: must reject even a canonical-iss valid token.
    expect(await verifyIdentityJwt(t, SECRET, { now: NOW })).toBeNull();
    await checkAgainstReference(t, SECRET, true, { allowedIssuers: [] });
  });

  it("V3c' canonical iss + allowlist=[] -> null (fail closed on empty)", async () => {
    const t = await mintWithJose(baseClaims());
    expect(
      await verifyIdentityJwt(t, SECRET, { now: NOW, allowedIssuers: [] }),
    ).toBeNull();
    await checkAgainstReference(t, SECRET, true, { allowedIssuers: [] });
  });

  it("V3d canonical iss + allowlist=[canonical] -> accept (happy path, exact)", async () => {
    const t = await mintWithJose(baseClaims());
    const got = await checkAgainstReference(t, SECRET, true, {
      allowedIssuers: [ISS],
    });
    expect(got?.subject).toBe("cail-subject-abc");
  });

  it("V4 nbf <= now present -> accept", async () => {
    const t = await mintWithJose(baseClaims({ nbf: NOW - 10 }));
    await checkAgainstReference(t, SECRET, true);
  });

  it("V5 extra unknown claims -> accept, extras dropped", async () => {
    const t = await mintWithJose(
      baseClaims({ scope: "openid", clientgrp: "GC", roles: ["x"] }),
    );
    const got = await checkAgainstReference(t, SECRET, true);
    expect(got).toEqual({
      subject: "cail-subject-abc",
      email: undefined,
      name: undefined,
      entitlements: [],
    });
    expect(got).not.toHaveProperty("scope");
    expect(got).not.toHaveProperty("clientgrp");
  });
});

// ===========================================================================
// Reject — structure / crypto
// ===========================================================================

describe("reject: structure & crypto", () => {
  it("V6 two-segment token (I1) -> null", async () => {
    const full = await mintWithJose(baseClaims());
    const [h, p] = full.split(".");
    const t = `${h}.${p}`;
    await checkAgainstReference(t, SECRET, false);
  });

  it("V7 non-base64url segment (I2) -> null", async () => {
    const full = await mintWithJose(baseClaims());
    const [, p, s] = full.split(".");
    const t = `not*base64url!.${p}.${s}`;
    expect(await verifyIdentityJwt(t, SECRET, { now: NOW, allowedIssuers: DEFAULT_ALLOW })).toBeNull();
    await checkAgainstReference(t, SECRET, false);
  });

  it("V8 payload = '[]' non-object JSON (I3) -> null", async () => {
    const header = b64urlStr(JSON.stringify({ alg: "HS256", typ: "JWT" }));
    const payload = b64urlStr("[]");
    // sign it properly so we prove I3 rejects even with a valid signature
    const signingInput = `${header}.${payload}`;
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sigBytes = new Uint8Array(
      await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signingInput)),
    );
    const { base64url } = await import("jose");
    const t = `${signingInput}.${base64url.encode(sigBytes)}`;
    await checkAgainstReference(t, SECRET, true);
  });

  it("V9 alg=none, empty sig (I4) -> null", async () => {
    const t = craftUnsigned({ alg: "none", typ: "JWT" }, baseClaims(), "");
    await checkAgainstReference(t, SECRET, false);
  });

  it("V10 alg=HS384 VALIDLY signed with real secret (I4 alg-agility) -> null", async () => {
    // Teeth: this token's HS384 signature IS valid under the shared secret, so
    // an alg-agile verifier that reads the alg from the token would accept it.
    // A correctly HS256-pinned verifier rejects at I4. The impl's HS256 check
    // would also fail (different digest), so sigValid=false either way.
    const t = await mintHmacAlg("HS384", baseClaims());
    expect(await verifyIdentityJwt(t, SECRET, { now: NOW, allowedIssuers: DEFAULT_ALLOW })).toBeNull();
    await checkAgainstReference(t, SECRET, false);
  });

  it("V10b alg=HS512 VALIDLY signed with real secret (I4 alg-agility) -> null", async () => {
    const t = await mintHmacAlg("HS512", baseClaims());
    expect(await verifyIdentityJwt(t, SECRET, { now: NOW, allowedIssuers: DEFAULT_ALLOW })).toBeNull();
    await checkAgainstReference(t, SECRET, false);
  });

  it("V11 alg=RS256 + RSA-shaped sig (I4/alg-confusion) -> null", async () => {
    const t = craftUnsigned(
      { alg: "RS256", typ: "JWT" },
      baseClaims(),
      "A".repeat(342),
    );
    await checkAgainstReference(t, SECRET, false);
  });

  // -- I4 ISOLATION: header alg mismatch but a genuinely-VALID HMAC-SHA256 sig.
  // These are the vectors with teeth for the alg PIN itself: the SHA-256
  // signature verifies (I5 passes), so acceptance is gated ONLY by I4. Remove
  // the alg check (keeping the hardcoded SHA-256 verify) and these FLIP to
  // accepted. V9/V10/V11 above cannot catch that — their signatures fail I5.
  it("V11a alg='HS384' header but valid SHA-256 sig (I4 pin isolated) -> null", async () => {
    const t = await signWithHeaderAlg(baseClaims(), "HS384", "SHA-256");
    // Sanity: the SHA-256 signature genuinely verifies (I5 would pass).
    expect(await verifyIdentityJwt(t, SECRET, { now: NOW, allowedIssuers: DEFAULT_ALLOW })).toBeNull();
    // Reference reader: sigValid=true (SHA-256 sig is valid) -> must reject at I4.
    await checkAgainstReference(t, SECRET, true);
  });

  it("V11b alg='none' header but valid SHA-256 sig (I4 pin isolated) -> null", async () => {
    const t = await signWithHeaderAlg(baseClaims(), "none", "SHA-256");
    expect(await verifyIdentityJwt(t, SECRET, { now: NOW, allowedIssuers: DEFAULT_ALLOW })).toBeNull();
    await checkAgainstReference(t, SECRET, true);
  });

  it("V11c control: alg='HS256' header + valid SHA-256 sig -> accept (proves V11a/b reject on alg, not sig)", async () => {
    const t = await signWithHeaderAlg(baseClaims(), "HS256", "SHA-256");
    const got = await checkAgainstReference(t, SECRET, true);
    expect(got?.subject).toBe("cail-subject-abc");
  });

  it("V12 valid claims signed with WRONG secret (I5) -> null", async () => {
    const t = await mintWithJose(baseClaims(), WRONG_SECRET);
    await checkAgainstReference(t, SECRET, false);
  });

  it("V13 payload byte flipped post-sign (I5) -> null", async () => {
    const t0 = await mintWithJose(baseClaims());
    const t = tamperPayloadByte(t0);
    await checkAgainstReference(t, SECRET, false);
  });
});

// ===========================================================================
// Reject — claims
// ===========================================================================

describe("reject: claims", () => {
  it("V14 no exp (I6) -> null", async () => {
    const c = baseClaims();
    delete (c as Record<string, unknown>).exp;
    const t = await mintWithJose(c);
    await checkAgainstReference(t, SECRET, true);
  });

  it("V17 exp is a string (I6) -> null", async () => {
    const t = await mintWithJose(baseClaims({ exp: "9999999999" }));
    await checkAgainstReference(t, SECRET, true);
  });

  it("V18a aud = cail-external (I7) -> null", async () => {
    const t = await mintWithJose(baseClaims({ aud: "cail-external" }));
    await checkAgainstReference(t, SECRET, true);
  });

  it("V18b aud missing (I7) -> null", async () => {
    const c = baseClaims();
    delete (c as Record<string, unknown>).aud;
    const t = await mintWithJose(c);
    await checkAgainstReference(t, SECRET, true);
  });

  it("V19 iss 'https://evil.example/cail-sso-not' + allowlist=[canonical] -> null", async () => {
    const t = await mintWithJose(
      baseClaims({ iss: "https://evil.example/cail-sso-not" }),
    );
    await checkAgainstReference(t, SECRET, true, { allowedIssuers: [ISS] });
  });

  // Codex-#3 REGRESSION VECTOR: this iss PASSES the old `endsWith("/cail-sso")`
  // suffix check but is NOT an allowlisted issuer. Exact allowlist must reject.
  it("V19b iss 'https://evil.example/cail-sso' (passes old suffix) + allowlist=[canonical] -> null", async () => {
    const t = await mintWithJose(
      baseClaims({ iss: "https://evil.example/cail-sso" }),
    );
    expect(
      await verifyIdentityJwt(t, SECRET, { now: NOW, allowedIssuers: [ISS] }),
    ).toBeNull();
    await checkAgainstReference(t, SECRET, true, { allowedIssuers: [ISS] });
  });

  it("V19c iss 'https://evil.example/cail-sso/extra' substring + allowlist=[canonical] -> null", async () => {
    const t = await mintWithJose(
      baseClaims({ iss: "https://evil.example/cail-sso/extra" }),
    );
    await checkAgainstReference(t, SECRET, true, { allowedIssuers: [ISS] });
  });

  it("V20a iss missing (I8) -> null", async () => {
    const c = baseClaims();
    delete (c as Record<string, unknown>).iss;
    const t = await mintWithJose(c);
    await checkAgainstReference(t, SECRET, true);
  });

  it("V20b iss non-string (I8) -> null", async () => {
    const t = await mintWithJose(baseClaims({ iss: 12345 }));
    await checkAgainstReference(t, SECRET, true);
  });

  it("V22 nbf present but string (I9) -> null", async () => {
    const t = await mintWithJose(baseClaims({ nbf: "1000000" }));
    await checkAgainstReference(t, SECRET, true);
  });

  it("V23 sub = '' (I10) -> null", async () => {
    const t = await mintWithJose(baseClaims({ sub: "" }));
    await checkAgainstReference(t, SECRET, true);
  });

  it("V24a sub missing (I10) -> null", async () => {
    const c = baseClaims();
    delete (c as Record<string, unknown>).sub;
    const t = await mintWithJose(c);
    await checkAgainstReference(t, SECRET, true);
  });

  it("V24b sub non-string (I10) -> null", async () => {
    const t = await mintWithJose(baseClaims({ sub: 42 }));
    await checkAgainstReference(t, SECRET, true);
  });
});

// ===========================================================================
// Clock-tolerance boundary (default tol=60, now=NOW)
// ===========================================================================

describe("clock tolerance (exp) default 60", () => {
  it("V15a exp == now -> accept (within tol)", async () => {
    const t = await mintWithJose(baseClaims({ exp: NOW }));
    const got = await checkAgainstReference(t, SECRET, true, { now: NOW });
    expect(got).not.toBeNull();
  });

  it("V15b exp == now-59 -> accept", async () => {
    const t = await mintWithJose(baseClaims({ exp: NOW - 59 }));
    const got = await verifyIdentityJwt(t, SECRET, { now: NOW, allowedIssuers: DEFAULT_ALLOW });
    expect(got).not.toBeNull();
    await checkAgainstReference(t, SECRET, true, { now: NOW });
  });

  it("V15c exp == now-60 -> null (tol boundary)", async () => {
    const t = await mintWithJose(baseClaims({ exp: NOW - 60 }));
    expect(await verifyIdentityJwt(t, SECRET, { now: NOW, allowedIssuers: DEFAULT_ALLOW })).toBeNull();
    await checkAgainstReference(t, SECRET, true, { now: NOW });
  });

  it("V15d exp == now-3600 -> null", async () => {
    const t = await mintWithJose(baseClaims({ exp: NOW - 3600 }));
    expect(await verifyIdentityJwt(t, SECRET, { now: NOW, allowedIssuers: DEFAULT_ALLOW })).toBeNull();
    await checkAgainstReference(t, SECRET, true, { now: NOW });
  });

  it("V16 exp == now+300 -> accept", async () => {
    const t = await mintWithJose(baseClaims({ exp: NOW + 300 }));
    const got = await verifyIdentityJwt(t, SECRET, { now: NOW, allowedIssuers: DEFAULT_ALLOW });
    expect(got).not.toBeNull();
  });

  it("V15e strict {tol:0} + exp == now -> null", async () => {
    const t = await mintWithJose(baseClaims({ exp: NOW }));
    expect(
      await verifyIdentityJwt(t, SECRET, { now: NOW, clockToleranceSeconds: 0, allowedIssuers: DEFAULT_ALLOW }),
    ).toBeNull();
    await checkAgainstReference(t, SECRET, true, {
      now: NOW,
      clockToleranceSeconds: 0,
    });
  });

  it("V15e' strict {tol:0} + exp == now+1 -> accept", async () => {
    const t = await mintWithJose(baseClaims({ exp: NOW + 1 }));
    expect(
      await verifyIdentityJwt(t, SECRET, { now: NOW, clockToleranceSeconds: 0, allowedIssuers: DEFAULT_ALLOW }),
    ).not.toBeNull();
  });
});

describe("clock tolerance (nbf) default 60", () => {
  it("V21a nbf == now+60 -> accept (within tol)", async () => {
    const t = await mintWithJose(baseClaims({ nbf: NOW + 60 }));
    const got = await verifyIdentityJwt(t, SECRET, { now: NOW, allowedIssuers: DEFAULT_ALLOW });
    expect(got).not.toBeNull();
    await checkAgainstReference(t, SECRET, true, { now: NOW });
  });

  it("V21b nbf == now+61 -> null", async () => {
    const t = await mintWithJose(baseClaims({ nbf: NOW + 61 }));
    expect(await verifyIdentityJwt(t, SECRET, { now: NOW, allowedIssuers: DEFAULT_ALLOW })).toBeNull();
    await checkAgainstReference(t, SECRET, true, { now: NOW });
  });

  it("V21c nbf == now-100 -> accept", async () => {
    const t = await mintWithJose(baseClaims({ nbf: NOW - 100 }));
    const got = await verifyIdentityJwt(t, SECRET, { now: NOW, allowedIssuers: DEFAULT_ALLOW });
    expect(got).not.toBeNull();
  });

  it("V21d strict {tol:0} + nbf == now -> accept", async () => {
    const t = await mintWithJose(baseClaims({ nbf: NOW }));
    expect(
      await verifyIdentityJwt(t, SECRET, { now: NOW, clockToleranceSeconds: 0, allowedIssuers: DEFAULT_ALLOW }),
    ).not.toBeNull();
  });

  it("V21d' strict {tol:0} + nbf == now+1 -> null", async () => {
    const t = await mintWithJose(baseClaims({ nbf: NOW + 1 }));
    expect(
      await verifyIdentityJwt(t, SECRET, { now: NOW, clockToleranceSeconds: 0, allowedIssuers: DEFAULT_ALLOW }),
    ).toBeNull();
  });
});

// ===========================================================================
// Fail-closed hardening
// ===========================================================================

describe("fail-closed hardening", () => {
  it("H1a empty secret rejects without throwing", async () => {
    const t = await mintWithJose(baseClaims());
    await expect(
      verifyIdentityJwt(t, "", { now: NOW, allowedIssuers: DEFAULT_ALLOW }),
    ).resolves.toBeNull();
  });

  it("H2a expired token with NaN now -> null", async () => {
    const t = await mintWithJose(baseClaims({ exp: NOW - 9999 }));
    expect(
      await verifyIdentityJwt(t, SECRET, {
        now: NaN,
        allowedIssuers: [ISS],
      }),
    ).toBeNull();
    await checkAgainstReference(t, SECRET, true, {
      now: NaN,
      allowedIssuers: [ISS],
    });
  });

  it("H2b expired token with NaN clockToleranceSeconds -> null", async () => {
    const t = await mintWithJose(baseClaims({ exp: NOW - 9999 }));
    expect(
      await verifyIdentityJwt(t, SECRET, {
        now: NOW,
        clockToleranceSeconds: NaN,
        allowedIssuers: [ISS],
      }),
    ).toBeNull();
    await checkAgainstReference(t, SECRET, true, {
      now: NOW,
      clockToleranceSeconds: NaN,
      allowedIssuers: [ISS],
    });
  });

  it("H2c future nbf with NaN now -> null", async () => {
    const t = await mintWithJose(baseClaims({ nbf: NOW + 9999 }));
    expect(
      await verifyIdentityJwt(t, SECRET, {
        now: NaN,
        allowedIssuers: [ISS],
      }),
    ).toBeNull();
    await checkAgainstReference(t, SECRET, true, {
      now: NaN,
      allowedIssuers: [ISS],
    });
  });

  it("H3a raw exp 1e400 (Infinity) -> null", async () => {
    const t = await signRawPayload(
      `{"sub":"cail-subject-abc","aud":${JSON.stringify(
        AUD,
      )},"iss":${JSON.stringify(ISS)},"exp":1e400}`,
    );
    expect(
      await verifyIdentityJwt(t, SECRET, {
        now: NOW,
        allowedIssuers: [ISS],
      }),
    ).toBeNull();
    await checkAgainstReference(t, SECRET, true, {
      now: NOW,
      allowedIssuers: [ISS],
    });
  });

  it("H3b raw nbf -1e400 (-Infinity) -> null", async () => {
    const t = await signRawPayload(
      `{"sub":"cail-subject-abc","aud":${JSON.stringify(
        AUD,
      )},"iss":${JSON.stringify(ISS)},"exp":${NOW + 3600},"nbf":-1e400}`,
    );
    expect(
      await verifyIdentityJwt(t, SECRET, {
        now: NOW,
        allowedIssuers: [ISS],
      }),
    ).toBeNull();
    await checkAgainstReference(t, SECRET, true, {
      now: NOW,
      allowedIssuers: [ISS],
    });
  });

  it("H2-control finite now keeps ordinary expired/fresh behavior", async () => {
    const expired = await mintWithJose(baseClaims({ exp: NOW - 9999 }));
    const fresh = await mintWithJose(baseClaims());
    expect(
      await verifyIdentityJwt(expired, SECRET, {
        now: NOW,
        allowedIssuers: [ISS],
      }),
    ).toBeNull();
    expect(
      await verifyIdentityJwt(fresh, SECRET, {
        now: NOW,
        allowedIssuers: [ISS],
      }),
    ).not.toBeNull();
  });
});

// ===========================================================================
// Output hygiene
// ===========================================================================

describe("output hygiene", () => {
  it("V25 entitlements filtered to strings", async () => {
    const t = await mintWithJose(
      baseClaims({ entitlements: ["a", 1, null, "b", { x: 1 }, true] }),
    );
    const got = await verifyIdentityJwt(t, SECRET, { now: NOW, allowedIssuers: DEFAULT_ALLOW });
    expect(got?.entitlements).toEqual(["a", "b"]);
  });

  it("V25b entitlements not an array -> []", async () => {
    const t = await mintWithJose(baseClaims({ entitlements: "a,b" }));
    const got = await verifyIdentityJwt(t, SECRET, { now: NOW, allowedIssuers: DEFAULT_ALLOW });
    expect(got?.entitlements).toEqual([]);
  });

  it("V25c malformed entitlements fail CLOSED: token stays accepted, privileges never elevate", async () => {
    // Wrong-typed claims collapse to [] — but the identity itself is still
    // returned (a producer bug must not become total access loss).
    for (const malformed of [
      { admin: true },
      null,
      42,
      true,
    ]) {
      const t = await mintWithJose(baseClaims({ entitlements: malformed }));
      const got = await verifyIdentityJwt(t, SECRET, {
        now: NOW,
        allowedIssuers: DEFAULT_ALLOW,
      });
      expect(got, "verified token must NOT be rejected").not.toBeNull();
      expect(got?.subject).toBe("cail-subject-abc");
      expect(got?.entitlements).toEqual([]);
    }
    // Array with non-string members: output is exactly the string members —
    // nothing is coerced INTO a privilege (no String() of objects/numbers).
    const t = await mintWithJose(
      baseClaims({ entitlements: [{ toString: "admin" }, 1, "real", ["admin"]] }),
    );
    const got = await verifyIdentityJwt(t, SECRET, {
      now: NOW,
      allowedIssuers: DEFAULT_ALLOW,
    });
    expect(got?.entitlements).toEqual(["real"]);
  });

  it("V26 email/name non-string -> undefined", async () => {
    const t = await mintWithJose(baseClaims({ email: 123, name: { x: 1 } }));
    const got = await verifyIdentityJwt(t, SECRET, { now: NOW, allowedIssuers: DEFAULT_ALLOW });
    expect(got?.email).toBeUndefined();
    expect(got?.name).toBeUndefined();
  });
});

// ===========================================================================
// Never throws + input not mutated + determinism
// ===========================================================================

describe("robustness", () => {
  const malformed: Array<[string, string]> = [
    ["empty string", ""],
    ["single segment", "abc"],
    ["two segments", "abc.def"],
    ["four segments", "a.b.c.d"],
    ["dots only", "..."],
    ["non-b64url", "@@@.@@@.@@@"],
    ["whitespace", "  .  .  "],
    ["huge", "A".repeat(100000) + ".B.C"],
  ];

  it("V27 never throws on malformed inputs", async () => {
    for (const [label, tok] of malformed) {
      await expect(
        verifyIdentityJwt(tok, SECRET, { now: NOW, allowedIssuers: DEFAULT_ALLOW }),
        `threw on: ${label}`,
      ).resolves.toBeNull();
    }
  });

  it("V27b never throws on crafted alg-confusion / claim garbage", async () => {
    const garbage = [
      craftUnsigned({ alg: "none" }, {}),
      craftUnsigned({}, baseClaims()),
      craftUnsigned({ alg: "HS256" }, { sub: null }),
      b64urlStr("not json") + ".",
    ];
    for (const g of garbage) {
      await expect(
        verifyIdentityJwt(g, SECRET, { now: NOW, allowedIssuers: DEFAULT_ALLOW }),
      ).resolves.toBeNull();
    }
  });

  it("V27c never throws on non-string token/secret (defensive)", async () => {
    // Cast through unknown to simulate a misbehaving caller.
    await expect(
      verifyIdentityJwt(null as unknown as string, SECRET, { now: NOW, allowedIssuers: DEFAULT_ALLOW }),
    ).resolves.toBeNull();
    await expect(
      verifyIdentityJwt("a.b.c", null as unknown as string, { now: NOW, allowedIssuers: DEFAULT_ALLOW }),
    ).resolves.toBeNull();
  });

  it("V28 does not mutate the token string or a shared claims object", async () => {
    const claims = baseClaims({ entitlements: ["a", 1, "b"] });
    const snapshot = JSON.parse(JSON.stringify(claims));
    const t = await mintWithJose(claims);
    const tokenCopy = `${t}`;
    await verifyIdentityJwt(t, SECRET, { now: NOW, allowedIssuers: DEFAULT_ALLOW });
    expect(claims).toEqual(snapshot); // caller's object untouched
    expect(t).toBe(tokenCopy); // string identity unchanged
  });

  it("V29 injected now respected: accept at now, reject after ttl", async () => {
    const t = await mintWithJose(baseClaims({ exp: NOW + 100 }));
    expect(await verifyIdentityJwt(t, SECRET, { now: NOW, allowedIssuers: DEFAULT_ALLOW })).not.toBeNull();
    // Push now well past exp + tol.
    expect(
      await verifyIdentityJwt(t, SECRET, { now: NOW + 100 + 61, allowedIssuers: DEFAULT_ALLOW }),
    ).toBeNull();
  });

  it("V29b default now (real clock) accepts fresh, rejects expired", async () => {
    // `now` omitted -> impl uses Date.now(); allowlist still required (I8).
    const nowReal = Math.floor(Date.now() / 1000);
    const fresh = await mintWithJose(baseClaims({ exp: nowReal + 3600 }));
    const stale = await mintWithJose(baseClaims({ exp: nowReal - 3600 }));
    expect(
      await verifyIdentityJwt(fresh, SECRET, { allowedIssuers: DEFAULT_ALLOW }),
    ).not.toBeNull();
    expect(
      await verifyIdentityJwt(stale, SECRET, { allowedIssuers: DEFAULT_ALLOW }),
    ).toBeNull();
  });
});
