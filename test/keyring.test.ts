import { describe, expect, it } from "vitest";
import {
  CAIL_GATEWAY_AUDIENCE,
  loadIdentityVerifierConfig,
  readIdentityKeyring,
  verifyIdentityJwt,
  verifyKeyringGatewayJwt,
  type IdentityVerifierConfig,
} from "../src/index.js";
import {
  TEST_SUBJECTS,
  createTestIdentityIssuer,
} from "../src/testing.js";
import { flipLowBit } from "./fixtures.js";

const NOW = 2_000_000;
const APP_AUDIENCE = "cail:site-studio";
const APP_JWT_HEADER = "x-cail-identity-jwt";
const GATEWAY_JWT_HEADER = "x-cail-gateway-identity-jwt";

const issuer = await createTestIdentityIssuer();

async function configFor(expectedAudience: string): Promise<IdentityVerifierConfig> {
  const loaded = await loadIdentityVerifierConfig({
    jwks: issuer.jwksJson,
    issuer: issuer.issuer,
    expectedAudience,
    now: NOW,
  });
  if (!loaded.ok) throw new Error(loaded.reason);
  return loaded.config;
}

function mint(audience: string, subject: string): Promise<string> {
  return issuer.mintIdentityJwt({ audience, subject, now: NOW });
}

const [appConfig, gatewayConfig, appJwt, gatewayJwt] = await Promise.all([
  configFor(APP_AUDIENCE),
  configFor(CAIL_GATEWAY_AUDIENCE),
  mint(APP_AUDIENCE, TEST_SUBJECTS.alice),
  mint(CAIL_GATEWAY_AUDIENCE, TEST_SUBJECTS.alice),
]);

describe("identity keyring transport", () => {
  it("round-trips a two-leg keyring through headers", () => {
    const headers = new Headers({
      [APP_JWT_HEADER]: appJwt,
      [GATEWAY_JWT_HEADER]: gatewayJwt,
    });
    expect(readIdentityKeyring(headers)).toEqual({ appJwt, gatewayJwt });
  });

  it("reads an app-only keyring when the gateway header is absent", () => {
    const headers = new Headers({ [APP_JWT_HEADER]: appJwt });
    expect(readIdentityKeyring(headers)).toEqual({ appJwt });
  });

  it("returns null when the identity header is absent", () => {
    expect(readIdentityKeyring(new Headers())).toBeNull();
  });

  it("rejects duplicate headers by construction", () => {
    const headers = new Headers({ [APP_JWT_HEADER]: appJwt });
    headers.append(GATEWAY_JWT_HEADER, gatewayJwt);
    headers.append(GATEWAY_JWT_HEADER, gatewayJwt);
    expect(readIdentityKeyring(headers)).toBeNull();
  });

  it("verifies matching Site/Agent-style app and Gateway legs", async () => {
    const keyring = readIdentityKeyring(
      new Headers({
        [APP_JWT_HEADER]: appJwt,
        [GATEWAY_JWT_HEADER]: gatewayJwt,
      }),
    )!;
    const appIdentity = await verifyIdentityJwt(keyring.appJwt, appConfig);
    await expect(
      verifyKeyringGatewayJwt(keyring, gatewayConfig, appIdentity!.subject),
    ).resolves.toMatchObject({ subject: TEST_SUBJECTS.alice });
  });

  it("returns null for an absent gateway leg", async () => {
    await expect(
      verifyKeyringGatewayJwt({ appJwt }, gatewayConfig, TEST_SUBJECTS.alice),
    ).resolves.toBeNull();
  });

  it("rejects a gateway leg belonging to a different person", async () => {
    const bobGateway = await mint(CAIL_GATEWAY_AUDIENCE, TEST_SUBJECTS.bob);
    await expect(
      verifyKeyringGatewayJwt(
        { appJwt, gatewayJwt: bobGateway },
        gatewayConfig,
        TEST_SUBJECTS.alice,
      ),
    ).resolves.toBeNull();
  });

  it("rejects an app-audience token smuggled into the gateway leg", async () => {
    await expect(
      verifyKeyringGatewayJwt(
        { appJwt, gatewayJwt: appJwt },
        gatewayConfig,
        TEST_SUBJECTS.alice,
      ),
    ).resolves.toBeNull();
  });

  it("rejects a gateway leg with a tampered signature", async () => {
    // A middle character carries only signature bits, so the spelling stays
    // canonical and only the signature check can reject the token.
    const forged = flipLowBit(gatewayJwt, gatewayJwt.length - 100);
    await expect(
      verifyKeyringGatewayJwt(
        { appJwt, gatewayJwt: forged },
        gatewayConfig,
        TEST_SUBJECTS.alice,
      ),
    ).resolves.toBeNull();
  });

  it("rejects an expired gateway leg", async () => {
    const expired = await issuer.mintIdentityJwt({
      audience: CAIL_GATEWAY_AUDIENCE,
      subject: TEST_SUBJECTS.alice,
      now: NOW - 3_600,
      expiresInSeconds: 1,
    });
    await expect(
      verifyKeyringGatewayJwt(
        { appJwt, gatewayJwt: expired },
        gatewayConfig,
        TEST_SUBJECTS.alice,
      ),
    ).resolves.toBeNull();
  });

  it("throws on a verifier config for a non-gateway audience", async () => {
    await expect(
      verifyKeyringGatewayJwt({ appJwt, gatewayJwt }, appConfig, TEST_SUBJECTS.alice),
    ).rejects.toThrow(TypeError);
  });

  it("throws on a non-canonical expected subject", async () => {
    await expect(
      verifyKeyringGatewayJwt(
        { appJwt, gatewayJwt },
        gatewayConfig,
        "user:alice@gc.cuny.edu",
      ),
    ).rejects.toThrow(TypeError);
  });
});
