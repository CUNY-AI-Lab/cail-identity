/**
 * Canonical-conformance vectors (2026-07 hardening pass):
 *
 *   S* — minimum secret length (RFC 7518 §3.2: an HS256 key MUST be at least
 *        as large as the hash output, 256 bits = 32 bytes; RFC 8725 §3.5 and
 *        the OWASP JWT cheat sheet: enforce strong symmetric keys). Web
 *        Crypto imports ANY key length, unlike jose, so without an explicit
 *        floor a misprovisioned 1-char secret verifies fine.
 *   U* — fatal UTF-8 decoding (RFC 7519 §7.2 / RFC 8725 §3.7: header and
 *        payload must be valid UTF-8 JSON; a lenient TextDecoder smuggles
 *        invalid bytes through as U+FFFD instead of rejecting).
 *   C* — `crit` header rejection (RFC 7515 §4.1.11: a verifier MUST reject a
 *        JWS whose header uses `crit` to name extensions it does not
 *        understand — this verifier implements none, so any `crit` rejects).
 *   B* — base64url canonicality (RFC 4648 §3.5: trailing padding bits MUST
 *        be zero; forgiving-base64 `atob` ignores them, making the token
 *        STRING malleable — same signature bytes, many encodings).
 */

import { describe, it, expect } from "vitest";
import { base64url } from "jose";
import { verifyIdentityJwt } from "../src/index.js";
import { SECRET, NOW, mintWithJose } from "./fixtures.js";

const ISS = "https://tools.ailab.gc.cuny.edu/cail-sso";
const OPTS = { now: NOW, allowedIssuers: [ISS] };

const enc = new TextEncoder();

function baseClaims(over: Record<string, unknown> = {}) {
  return {
    sub: "cail-subject-abc",
    aud: "cail-internal",
    iss: ISS,
    exp: NOW + 3600,
    ...over,
  };
}

/** HS256-sign arbitrary raw header/payload BYTES with Web Crypto. */
async function hs256SignSegments(
  headerB64: string,
  payloadB64: string,
  secret: string,
): Promise<string> {
  const signingInput = `${headerB64}.${payloadB64}`;
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, enc.encode(signingInput)),
  );
  return `${signingInput}.${base64url.encode(sig)}`;
}

/** Valid HS256 token with an arbitrary header OBJECT (jose pins alg to the
 * hash, so crafting `crit` etc. requires signing the segments directly). */
async function signWithHeader(
  header: Record<string, unknown>,
  claims: Record<string, unknown>,
  secret: string = SECRET,
): Promise<string> {
  return hs256SignSegments(
    base64url.encode(enc.encode(JSON.stringify(header))),
    base64url.encode(enc.encode(JSON.stringify(claims))),
    secret,
  );
}

/** Valid HS256 token whose payload segment encodes arbitrary raw BYTES
 * (not necessarily valid UTF-8). */
async function signRawPayloadBytes(
  payloadBytes: Uint8Array,
  secret: string = SECRET,
): Promise<string> {
  return hs256SignSegments(
    base64url.encode(enc.encode(JSON.stringify({ alg: "HS256", typ: "JWT" }))),
    base64url.encode(payloadBytes),
    secret,
  );
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// ===========================================================================
// S — minimum secret length (RFC 7518 §3.2)
// ===========================================================================

describe("secret minimum length (RFC 7518 §3.2)", () => {
  it("S1 1-char secret -> null even though its signature is valid", async () => {
    const t = await mintWithJose(baseClaims(), "x");
    // Minted AND verified with the same secret: the only ground for
    // rejection is the key-length floor, not the signature.
    expect(await verifyIdentityJwt(t, "x", OPTS)).toBeNull();
  });

  it("S2 31-byte secret -> null (one byte under the floor)", async () => {
    const s = "a".repeat(31);
    const t = await mintWithJose(baseClaims(), s);
    expect(await verifyIdentityJwt(t, s, OPTS)).toBeNull();
  });

  it("S3 32-byte secret -> accepted (floor is inclusive)", async () => {
    const s = "a".repeat(32);
    const t = await mintWithJose(baseClaims(), s);
    const got = await verifyIdentityJwt(t, s, OPTS);
    expect(got?.subject).toBe("cail-subject-abc");
  });

  it("S4 floor is measured in UTF-8 BYTES, not characters", async () => {
    // 31 characters, but "é" is 2 UTF-8 bytes -> 32 bytes total: accepted.
    const s = "é" + "a".repeat(30);
    expect(s.length).toBe(31);
    expect(enc.encode(s).length).toBe(32);
    const t = await mintWithJose(baseClaims(), s);
    const got = await verifyIdentityJwt(t, s, OPTS);
    expect(got?.subject).toBe("cail-subject-abc");
  });
});

// ===========================================================================
// U — fatal UTF-8 decode (RFC 7519 §7.2 / RFC 8725 §3.7)
// ===========================================================================

describe("fatal UTF-8 payload decoding", () => {
  it("U1 invalid UTF-8 byte inside the payload -> null", async () => {
    // 0xFF can never appear in well-formed UTF-8. A lenient decoder turns it
    // into U+FFFD, yielding parseable JSON with sub "a�b" — accepted.
    // A conforming verifier rejects the byte stream outright.
    const payload = concatBytes(
      enc.encode('{"sub":"a'),
      Uint8Array.of(0xff),
      enc.encode(
        `b","aud":"cail-internal","iss":${JSON.stringify(ISS)},"exp":${
          NOW + 3600
        }}`,
      ),
    );
    const t = await signRawPayloadBytes(payload);
    expect(await verifyIdentityJwt(t, SECRET, OPTS)).toBeNull();
  });

  it("U1-control a LITERAL U+FFFD (validly encoded) is still accepted", async () => {
    // Proves U1 rejects the malformed BYTES, not the replacement character.
    const t = await mintWithJose(baseClaims({ sub: "a�b" }));
    const got = await verifyIdentityJwt(t, SECRET, OPTS);
    expect(got?.subject).toBe("a�b");
  });
});

// ===========================================================================
// C — crit header rejection (RFC 7515 §4.1.11)
// ===========================================================================

describe("crit header rejection", () => {
  it("C1 validly-signed token with crit:[\"exp\"] -> null", async () => {
    const t = await signWithHeader(
      { alg: "HS256", typ: "JWT", crit: ["exp"] },
      baseClaims(),
    );
    expect(await verifyIdentityJwt(t, SECRET, OPTS)).toBeNull();
  });

  it("C2 ANY own crit member rejects, even crit:[]", async () => {
    const t = await signWithHeader(
      { alg: "HS256", typ: "JWT", crit: [] },
      baseClaims(),
    );
    expect(await verifyIdentityJwt(t, SECRET, OPTS)).toBeNull();
  });

  it("C-control identical header WITHOUT crit -> accepted", async () => {
    const t = await signWithHeader({ alg: "HS256", typ: "JWT" }, baseClaims());
    const got = await verifyIdentityJwt(t, SECRET, OPTS);
    expect(got?.subject).toBe("cail-subject-abc");
  });
});

// ===========================================================================
// B — base64url canonicality (RFC 4648 §3.5)
// ===========================================================================

describe("base64url canonicality", () => {
  const ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  it("B1 signature segment with non-zero trailing pad bits -> null", async () => {
    const t = await mintWithJose(baseClaims());
    const [h, p, s] = t.split(".");
    // 32-byte HS256 sig -> 43 base64url chars -> the last char carries 2
    // trailing padding bits that MUST be zero (RFC 4648 §3.5).
    expect(s!.length % 4).toBe(3);
    const lastIdx = ALPHABET.indexOf(s![s!.length - 1]!);
    // Flip the lowest bit: same decoded bytes under forgiving-base64, a
    // DIFFERENT token string. jose only ever mints canonical segments.
    const mutated = s!.slice(0, -1) + ALPHABET[lastIdx ^ 1];
    expect(mutated).not.toBe(s);
    // Sanity: a forgiving decoder yields the SAME signature bytes.
    expect(Buffer.from(mutated, "base64url")).toEqual(
      Buffer.from(s!, "base64url"),
    );
    expect(await verifyIdentityJwt(`${h}.${p}.${mutated}`, SECRET, OPTS)).toBeNull();
  });

  it("B1-control the canonical original still verifies", async () => {
    const t = await mintWithJose(baseClaims());
    const got = await verifyIdentityJwt(t, SECRET, OPTS);
    expect(got?.subject).toBe("cail-subject-abc");
  });
});
