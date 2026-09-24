import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  CAIL_GATEWAY_AUDIENCE,
  loadIdentityVerifierConfig,
  readIdentityKeyring,
  verifyIdentityJwt,
  verifyKeyringGatewayJwt,
} from "../src/index.js";
import { TEST_SUBJECTS, createTestIdentityIssuer } from "../src/testing.js";

interface LegSchema {
  minLength: number;
  maxLength: number;
  pattern: string;
  $comment: string;
}

// SAFETY: this checked-in contract fixture is parsed only for the schema
// fields declared here; each test compares them against keyring behavior.
const contract = JSON.parse(
  readFileSync(
    new URL("../contract/identity-keyring-v1.json", import.meta.url),
    "utf8",
  ),
) as {
  required: string[];
  properties: { app_jwt: LegSchema; gateway_jwt: LegSchema };
  examples: Array<{ app_jwt: string; gateway_jwt: string }>;
};

const { app_jwt: appLeg, gateway_jwt: gatewayLeg } = contract.properties;

/** Each leg's `$comment` names its transport header: "Header <name>. ...". */
function headerOf(leg: LegSchema): string {
  const header = /^Header ([a-z-]+)\./.exec(leg.$comment)?.[1];
  if (header === undefined) throw new Error("leg $comment names no header");
  return header;
}

/** The gateway leg's `$comment` pins its audience: "aud = '<audience>'". */
function gatewayAudience(): string {
  const audience = /aud = '([^']+)'/.exec(gatewayLeg.$comment)?.[1];
  if (audience === undefined) throw new Error("gateway leg names no audience");
  return audience;
}

function contractAccepts(leg: LegSchema, value: string): boolean {
  return (
    value.length >= leg.minLength &&
    value.length <= leg.maxLength &&
    new RegExp(leg.pattern, "u").test(value)
  );
}

function compactOfLength(length: number): string {
  return `a.b.${"c".repeat(length - 4)}`;
}

describe("identity-keyring-v1 contract", () => {
  const [example] = contract.examples;

  it("reads each contract example from the contract's headers", () => {
    for (const value of contract.examples) {
      const headers = new Headers({
        [headerOf(appLeg)]: value.app_jwt,
        [headerOf(gatewayLeg)]: value.gateway_jwt,
      });
      expect(readIdentityKeyring(headers)).toEqual({
        appJwt: value.app_jwt,
        gatewayJwt: value.gateway_jwt,
      });
    }
  });

  it("requires exactly the contract's required legs", () => {
    expect(contract.required).toEqual(["app_jwt"]);
    expect(
      readIdentityKeyring(
        new Headers({ [headerOf(gatewayLeg)]: example!.gateway_jwt }),
      ),
    ).toBeNull();
    expect(
      readIdentityKeyring(new Headers({ [headerOf(appLeg)]: example!.app_jwt })),
    ).toEqual({ appJwt: example!.app_jwt });
  });

  it("accepts exactly the leg values the contract accepts", () => {
    for (const [leg, other, otherValue] of [
      [appLeg, gatewayLeg, example!.gateway_jwt],
      [gatewayLeg, appLeg, example!.app_jwt],
    ] as const) {
      const candidates = [
        example!.app_jwt,
        "",
        "a.b",
        "a.b.c",
        "a.b.c.d",
        "a..c",
        "a.b.c=",
        "a+b.c.d",
        "a.b.c ",
        `${example!.app_jwt},${example!.app_jwt}`,
        compactOfLength(leg.maxLength),
        compactOfLength(leg.maxLength + 1),
      ];
      for (const value of candidates) {
        const headers = new Headers({ [headerOf(other)]: otherValue });
        headers.set(headerOf(leg), value);
        const accepted = readIdentityKeyring(headers) !== null;
        expect(accepted, `${headerOf(leg)}: ${value.slice(0, 40)}`).toBe(
          contractAccepts(leg, headers.get(headerOf(leg)) ?? ""),
        );
      }
    }
  });

  it("verifies a gateway leg only for the contract audience and app-leg subject", async () => {
    const audience = gatewayAudience();
    expect(CAIL_GATEWAY_AUDIENCE).toBe(audience);
    const issuer = await createTestIdentityIssuer();
    const appAudience = "cail:site-studio";
    const mint = (aud: string, subject: string) =>
      issuer.mintIdentityJwt({ audience: aud, subject });
    const load = async (expectedAudience: string) => {
      const loaded = await loadIdentityVerifierConfig({
        jwks: issuer.jwksJson,
        issuer: issuer.issuer,
        expectedAudience,
      });
      if (!loaded.ok) throw new Error(loaded.reason);
      return loaded.config;
    };
    const [appConfig, gatewayConfig] = await Promise.all([
      load(appAudience),
      load(audience),
    ]);

    const appJwt = await mint(appAudience, TEST_SUBJECTS.alice);
    const appIdentity = await verifyIdentityJwt(appJwt, appConfig);
    expect(appIdentity?.subject).toBe(TEST_SUBJECTS.alice);

    const keyringFor = async (aud: string, subject: string) =>
      readIdentityKeyring(
        new Headers({
          [headerOf(appLeg)]: appJwt,
          [headerOf(gatewayLeg)]: await mint(aud, subject),
        }),
      )!;

    await expect(
      verifyKeyringGatewayJwt(
        await keyringFor(audience, TEST_SUBJECTS.alice),
        gatewayConfig,
        appIdentity!.subject,
      ),
    ).resolves.toMatchObject({ subject: TEST_SUBJECTS.alice });
    await expect(
      verifyKeyringGatewayJwt(
        await keyringFor(audience, TEST_SUBJECTS.bob),
        gatewayConfig,
        appIdentity!.subject,
      ),
    ).resolves.toBeNull();
    await expect(
      verifyKeyringGatewayJwt(
        await keyringFor(appAudience, TEST_SUBJECTS.alice),
        gatewayConfig,
        appIdentity!.subject,
      ),
    ).resolves.toBeNull();
    await expect(
      verifyKeyringGatewayJwt(
        await keyringFor(audience, TEST_SUBJECTS.alice),
        appConfig,
        appIdentity!.subject,
      ),
    ).rejects.toThrow(TypeError);
  });
});
