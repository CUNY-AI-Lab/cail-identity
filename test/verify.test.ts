import { describe, expect, it } from "vitest";
import { SignJWT, base64url } from "jose";
import {
  loadIdentityVerifierConfig,
  verifyIdentityJwt,
  type LoadIdentityVerifierConfigInput,
} from "../src/index.js";
import {
  encodeJson,
  makeRsaFixture,
  mintRsaJwt,
  signSegments,
  withPaddingBitSet,
  type JsonObject,
} from "./fixtures.js";

const NOW = 1_000_000;
const ISS = "https://issuer.example/cail-sso";
const OTHER_ISS = "https://other-issuer.example/cail-sso";
const AUD = "cail-internal";

const [oldKey, newKey] = await Promise.all([
  makeRsaFixture("old-2026-07"),
  makeRsaFixture("new-2026-08"),
]);

function claims(over: JsonObject = {}): JsonObject {
  return {
    sub: "cail-0123456789abcdef0123456789abcdef",
    aud: AUD,
    iss: ISS,
    exp: NOW + 3600,
    ...over,
  };
}

async function verify(
  token: string,
  over: Partial<LoadIdentityVerifierConfigInput> = {},
) {
  const loaded = await loadIdentityVerifierConfig({
    jwks: JSON.stringify(oldKey.jwks),
    issuer: ISS,
    expectedAudience: AUD,
    supportedIssuers: [ISS],
    now: NOW,
    ...over,
  });
  if (!loaded.ok) throw new Error(`invalid test config: ${loaded.reason}`);
  return verifyIdentityJwt(token, loaded.config);
}

// Hand-built segments. Every token below is signed over its exact segments,
// so the signature check passes and only the rule under test can reject it.
const HEADER = encodeJson({ alg: "RS256", kid: oldKey.kid });
const PAYLOAD = encodeJson(claims({ note: "x" }));

/** JSON for `value` plus an ignored `note` string member holding a lone 0xff byte. */
function encodeJsonWithInvalidUtf8(value: JsonObject): string {
  const encoder = new TextEncoder();
  const json = JSON.stringify(value);
  return base64url.encode(
    Uint8Array.of(
      ...encoder.encode(`${json.slice(0, -1)},"note":"`),
      0xff,
      ...encoder.encode('"}'),
    ),
  );
}

describe("verifyIdentityJwt happy path and output", () => {
  it("accepts a minimal RS256 token and returns the canonical identity shape", async () => {
    const result = await verify(await mintRsaJwt(claims(), oldKey));
    expect(result).toEqual({
      subject: "cail-0123456789abcdef0123456789abcdef",
      email: undefined,
      name: undefined,
      entitlements: [],
    });
  });

  it("maps optional identity claims and drops unknown claims", async () => {
    const token = await mintRsaJwt(
      claims({
        email: "user@gc.cuny.edu",
        name: "Ada Lovelace",
        entitlements: ["a", 1, "b"],
        role: "ignored",
      }),
      oldKey,
    );
    expect(await verify(token)).toEqual({
      subject: "cail-0123456789abcdef0123456789abcdef",
      email: "user@gc.cuny.edu",
      name: "Ada Lovelace",
      entitlements: ["a", "b"],
    });
  });

  it("accepts a token signed over hand-built segments", async () => {
    await expect(
      verify(await signSegments(HEADER, PAYLOAD, oldKey)),
    ).resolves.not.toBeNull();
  });
});

describe("verifyIdentityJwt structure, encoding, and JSON", () => {
  it.each(["", "a.b", "a.b.c.d", "a.*.c"])("rejects malformed compact JWT %j", async (token) => {
    expect(await verify(token)).toBeNull();
  });

  it.each([
    ["header", () => signSegments(encodeJson([]), PAYLOAD, oldKey)],
    ["payload", () => signSegments(HEADER, encodeJson([]), oldKey)],
  ])("rejects a signed token whose %s is not a JSON object", async (_segment, mint) => {
    expect(await verify(await mint())).toBeNull();
  });

  it.each([
    [
      "header",
      () =>
        signSegments(
          encodeJsonWithInvalidUtf8({ alg: "RS256", kid: oldKey.kid }),
          PAYLOAD,
          oldKey,
        ),
    ],
    [
      "payload",
      () => signSegments(HEADER, encodeJsonWithInvalidUtf8(claims()), oldKey),
    ],
  ])("rejects a signed token with invalid UTF-8 in the %s", async (_segment, mint) => {
    expect(await verify(await mint())).toBeNull();
  });

  it.each([
    ["header", () => signSegments(withPaddingBitSet(HEADER), PAYLOAD, oldKey)],
    ["payload", () => signSegments(HEADER, withPaddingBitSet(PAYLOAD), oldKey)],
    [
      "signature",
      async () => {
        const [, , signature] = (await signSegments(HEADER, PAYLOAD, oldKey)).split(".");
        return `${HEADER}.${PAYLOAD}.${withPaddingBitSet(signature!)}`;
      },
    ],
  ])("rejects a non-canonical base64url %s segment", async (_segment, mint) => {
    expect(await verify(await mint())).toBeNull();
  });
});

describe("verifyIdentityJwt algorithm and key selection", () => {
  it.each([undefined, "", 7])("rejects missing or invalid kid %j", async (kid) => {
    const token = await mintRsaJwt(claims(), oldKey, { kid });
    expect(await verify(token)).toBeNull();
  });

  it("rejects an unknown kid", async () => {
    const token = await mintRsaJwt(claims(), oldKey, { kid: "unknown" });
    expect(await verify(token)).toBeNull();
  });

  it("rejects alg confusion even when an HS256 signature is valid", async () => {
    const secret = new TextEncoder().encode(oldKey.publicJwk.n!);
    const token = await new SignJWT(claims())
      .setProtectedHeader({ alg: "HS256", kid: oldKey.kid })
      .sign(secret);
    expect(await verify(token)).toBeNull();
  });

  it.each([
    { alg: "none" },
    { alg: "PS256" },
    { alg: "RS256", crit: [] },
    { alg: "RS256", crit: ["b64"], b64: true },
  ])("rejects header %j even with a valid RS256 signature", async (header) => {
    const token = await signSegments(
      encodeJson({ kid: oldKey.kid, ...header }),
      PAYLOAD,
      oldKey,
    );
    expect(await verify(token)).toBeNull();
  });

  it.each([false, "false", 0, null])(
    "rejects malformed or unencoded-payload b64 header %j",
    async (b64) => {
      const token = await mintRsaJwt(claims(), oldKey, { b64 });
      expect(await verify(token)).toBeNull();
    },
  );

  it("rejects a valid token signed by a different key under the selected kid", async () => {
    const token = await mintRsaJwt(claims(), newKey, { kid: oldKey.kid });
    expect(await verify(token)).toBeNull();
  });
});

describe("verifyIdentityJwt audience, issuer, and subject", () => {
  it.each([undefined, "", "other"])("rejects audience %j", async (aud) => {
    expect(await verify(await mintRsaJwt(claims({ aud }), oldKey))).toBeNull();
  });

  it.each([
    { aud: [AUD] },
    { aud: ["service-a", AUD, "service-b"] },
  ])(
    "rejects array audience $aud even when it contains the service audience",
    async ({ aud }) => {
      expect(await verify(await mintRsaJwt(claims({ aud }), oldKey))).toBeNull();
    },
  );

  it.each([undefined, "", OTHER_ISS, 7])("rejects issuer %j", async (iss) => {
    expect(await verify(await mintRsaJwt(claims({ iss }), oldKey))).toBeNull();
  });

  it.each([
    `${ISS}/`,
    `${ISS}.evil.example`,
    `https://evil.example/${ISS}`,
    ISS.toUpperCase(),
  ])("rejects issuer near-miss %j", async (iss) => {
    expect(await verify(await mintRsaJwt(claims({ iss }), oldKey))).toBeNull();
  });

  it("snapshots one exact issuer from an explicitly supplied authority", async () => {
    const token = await mintRsaJwt(claims(), oldKey);
    expect(
      await verify(token, { supportedIssuers: [ISS, OTHER_ISS] }),
    ).not.toBeNull();
  });

  it.each([
    undefined,
    "",
    7,
    "cail-subject",
    "cail-0123456789ABCDEF0123456789ABCDEF",
    "cail-0123456789abcdef0123456789abcde",
    " cail-0123456789abcdef0123456789abcdef",
  ])("rejects subject %j", async (sub) => {
    expect(await verify(await mintRsaJwt(claims({ sub }), oldKey))).toBeNull();
  });
});

describe("verifyIdentityJwt time", () => {
  // A tolerance of undefined means the default of 60 seconds.
  it.each([
    { exp: NOW - 60, tolerance: undefined, accepted: false },
    { exp: NOW - 59, tolerance: undefined, accepted: true },
    { exp: NOW, tolerance: 0, accepted: false },
  ])(
    "exp $exp at tolerance $tolerance is accepted: $accepted",
    async ({ exp, tolerance, accepted }) => {
      const token = await mintRsaJwt(claims({ exp }), oldKey);
      const result = await verify(token, { clockToleranceSeconds: tolerance });
      expect(result !== null).toBe(accepted);
    },
  );

  it.each([
    { nbf: NOW + 60, tolerance: undefined, accepted: true },
    { nbf: NOW + 61, tolerance: undefined, accepted: false },
    { nbf: NOW, tolerance: 0, accepted: true },
  ])(
    "nbf $nbf at tolerance $tolerance is accepted: $accepted",
    async ({ nbf, tolerance, accepted }) => {
      const token = await mintRsaJwt(claims({ nbf }), oldKey);
      const result = await verify(token, { clockToleranceSeconds: tolerance });
      expect(result !== null).toBe(accepted);
    },
  );

  it.each([undefined, "9999999", Number.NaN, Number.POSITIVE_INFINITY])(
    "rejects invalid exp %j",
    async (exp) => {
      expect(await verify(await mintRsaJwt(claims({ exp }), oldKey))).toBeNull();
    },
  );

  it.each(["0", Number.NaN, Number.NEGATIVE_INFINITY])("rejects invalid nbf %j", async (nbf) => {
    expect(await verify(await mintRsaJwt(claims({ nbf }), oldKey))).toBeNull();
  });

  it.each(["0", null, {}, true])("rejects invalid iat %j when present", async (iat) => {
    expect(await verify(await mintRsaJwt(claims({ iat }), oldKey))).toBeNull();
  });
});

describe("verifyIdentityJwt fail-closed behavior", () => {
  it("returns null rather than throwing for a wrong token runtime type", async () => {
    // SAFETY: this deliberately injects a wrong runtime token type to verify
    // the public fail-closed boundary.
    await expect(verify(null as never)).resolves.toBeNull();
  });
});
