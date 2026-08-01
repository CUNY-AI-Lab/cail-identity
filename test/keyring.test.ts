import { describe, expect, it } from "vitest";
import {
  CAIL_GATEWAY_AUDIENCE,
  CAIL_GATEWAY_IDENTITY_JWT_HEADER,
  CAIL_IDENTITY_JWT_HEADER,
  identityKeyringHeaders,
  loadIdentityVerifierConfig,
  readIdentityKeyring,
  verifyKeyringGatewayJwt,
} from "../src/index";
import {
  TEST_SUBJECTS,
  createTestIdentityIssuer,
} from "../src/testing";

const APP_AUDIENCE = "cail:site-studio";

async function keyringFixture() {
  const issuer = await createTestIdentityIssuer();
  const appJwt = await issuer.mintIdentityJwt({
    audience: APP_AUDIENCE,
    subject: TEST_SUBJECTS.alice,
  });
  const gatewayJwt = await issuer.mintIdentityJwt({
    audience: CAIL_GATEWAY_AUDIENCE,
    subject: TEST_SUBJECTS.alice,
  });
  const loaded = await loadIdentityVerifierConfig({
    jwks: issuer.jwksJson,
    issuer: issuer.issuer,
    expectedAudience: CAIL_GATEWAY_AUDIENCE,
  });
  if (!loaded.ok) throw new Error(loaded.reason);
  return { issuer, appJwt, gatewayJwt, gatewayConfig: loaded.config };
}

describe("identity keyring transport", () => {
  it("round-trips a two-leg keyring through headers", async () => {
    const { appJwt, gatewayJwt } = await keyringFixture();
    const headers = new Headers(
      identityKeyringHeaders({ appJwt, gatewayJwt }),
    );
    expect(readIdentityKeyring(headers)).toEqual({ appJwt, gatewayJwt });
  });

  it("reads an app-only keyring when the gateway header is absent", async () => {
    const { appJwt } = await keyringFixture();
    const headers = new Headers({ [CAIL_IDENTITY_JWT_HEADER]: appJwt });
    expect(readIdentityKeyring(headers)).toEqual({ appJwt });
  });

  it("returns null when the identity header is absent", () => {
    expect(readIdentityKeyring(new Headers())).toBeNull();
  });

  it("fails the whole keyring closed on a malformed leg", async () => {
    const { appJwt, gatewayJwt } = await keyringFixture();
    for (const bad of ["", "not-a-jwt", "a.b", `${gatewayJwt},${gatewayJwt}`]) {
      const badGateway = new Headers({
        [CAIL_IDENTITY_JWT_HEADER]: appJwt,
        [CAIL_GATEWAY_IDENTITY_JWT_HEADER]: bad,
      });
      expect(readIdentityKeyring(badGateway)).toBeNull();
      const badApp = new Headers({
        [CAIL_IDENTITY_JWT_HEADER]: bad,
        [CAIL_GATEWAY_IDENTITY_JWT_HEADER]: gatewayJwt,
      });
      expect(readIdentityKeyring(badApp)).toBeNull();
    }
  });

  it("rejects duplicate headers by construction", async () => {
    const { appJwt, gatewayJwt } = await keyringFixture();
    const headers = new Headers({ [CAIL_IDENTITY_JWT_HEADER]: appJwt });
    headers.append(CAIL_GATEWAY_IDENTITY_JWT_HEADER, gatewayJwt);
    headers.append(CAIL_GATEWAY_IDENTITY_JWT_HEADER, gatewayJwt);
    expect(readIdentityKeyring(headers)).toBeNull();
  });

  it("refuses to emit a malformed keyring", async () => {
    const { appJwt } = await keyringFixture();
    expect(() =>
      identityKeyringHeaders({ appJwt, gatewayJwt: "nope" }),
    ).toThrow(TypeError);
    expect(() => identityKeyringHeaders({ appJwt: "" })).toThrow(TypeError);
  });

  it("verifies a matching gateway leg to the app-leg subject", async () => {
    const { appJwt, gatewayJwt, gatewayConfig } = await keyringFixture();
    const identity = await verifyKeyringGatewayJwt(
      { appJwt, gatewayJwt },
      gatewayConfig,
      TEST_SUBJECTS.alice,
    );
    expect(identity?.subject).toBe(TEST_SUBJECTS.alice);
  });

  it("returns null for an absent gateway leg", async () => {
    const { appJwt, gatewayConfig } = await keyringFixture();
    expect(
      await verifyKeyringGatewayJwt({ appJwt }, gatewayConfig, TEST_SUBJECTS.alice),
    ).toBeNull();
  });

  it("rejects a gateway leg belonging to a different person", async () => {
    const { issuer, appJwt, gatewayConfig } = await keyringFixture();
    const bobGateway = await issuer.mintIdentityJwt({
      audience: CAIL_GATEWAY_AUDIENCE,
      subject: TEST_SUBJECTS.bob,
    });
    expect(
      await verifyKeyringGatewayJwt(
        { appJwt, gatewayJwt: bobGateway },
        gatewayConfig,
        TEST_SUBJECTS.alice,
      ),
    ).toBeNull();
  });

  it("rejects an app-audience token smuggled into the gateway leg", async () => {
    const { issuer, appJwt, gatewayConfig } = await keyringFixture();
    const wrongAudience = await issuer.mintIdentityJwt({
      audience: APP_AUDIENCE,
      subject: TEST_SUBJECTS.alice,
    });
    expect(
      await verifyKeyringGatewayJwt(
        { appJwt, gatewayJwt: wrongAudience },
        gatewayConfig,
        TEST_SUBJECTS.alice,
      ),
    ).toBeNull();
  });

  it("rejects a forged gateway leg", async () => {
    const { appJwt, gatewayJwt, gatewayConfig } = await keyringFixture();
    const forged = `${gatewayJwt.slice(0, -2)}${gatewayJwt.endsWith("aa") ? "bb" : "aa"}`;
    expect(
      await verifyKeyringGatewayJwt(
        { appJwt, gatewayJwt: forged },
        gatewayConfig,
        TEST_SUBJECTS.alice,
      ),
    ).toBeNull();
  });

  it("rejects an expired gateway leg", async () => {
    const { issuer, appJwt, gatewayConfig } = await keyringFixture();
    const expired = await issuer.mintIdentityJwt({
      audience: CAIL_GATEWAY_AUDIENCE,
      subject: TEST_SUBJECTS.alice,
      now: Math.floor(Date.now() / 1_000) - 3_600,
      expiresInSeconds: 1,
    });
    expect(
      await verifyKeyringGatewayJwt(
        { appJwt, gatewayJwt: expired },
        gatewayConfig,
        TEST_SUBJECTS.alice,
      ),
    ).toBeNull();
  });

  it("throws on a non-gateway verifier config or bad expected subject", async () => {
    const { issuer, appJwt, gatewayJwt } = await keyringFixture();
    const appConfig = await loadIdentityVerifierConfig({
      jwks: issuer.jwksJson,
      issuer: issuer.issuer,
      expectedAudience: APP_AUDIENCE,
    });
    if (!appConfig.ok) throw new Error(appConfig.reason);
    await expect(
      verifyKeyringGatewayJwt(
        { appJwt, gatewayJwt },
        appConfig.config,
        TEST_SUBJECTS.alice,
      ),
    ).rejects.toThrow(TypeError);
    const { gatewayConfig } = await keyringFixture();
    await expect(
      verifyKeyringGatewayJwt(
        { appJwt, gatewayJwt },
        gatewayConfig,
        "user:alice@gc.cuny.edu",
      ),
    ).rejects.toThrow(TypeError);
  });
});
