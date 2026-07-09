import { afterEach, describe, expect, it } from "vitest";
import { verifyIdentityJwt } from "../src/index.js";
import { mintWithJose, signRawPayload, SECRET, NOW } from "./fixtures.js";

const ISS = "https://tools.ailab.gc.cuny.edu/cail-sso";
const OK = { now: NOW, allowedIssuers: [ISS] };
const goodClaims = {
  sub: "subject-1",
  aud: "cail-internal",
  iss: ISS,
  exp: NOW + 3600,
};
const pollutedPrototype = Object.prototype as Record<string, unknown>;

afterEach(() => {
  delete pollutedPrototype.entitlements;
  delete pollutedPrototype.email;
  delete pollutedPrototype.name;
  delete pollutedPrototype.alg;
});

describe("prototype-chain claim reads", () => {
  it("ignores inherited optional identity claims", async () => {
    pollutedPrototype.entitlements = ["admin", "root"];
    pollutedPrototype.email = "attacker@evil";
    pollutedPrototype.name = "Mallory";

    const token = await mintWithJose(goodClaims);

    expect(await verifyIdentityJwt(token, SECRET, OK)).toEqual({
      subject: "subject-1",
      entitlements: [],
      email: undefined,
      name: undefined,
    });
  });

  it("preserves own optional identity claims", async () => {
    pollutedPrototype.entitlements = ["admin", "root"];
    pollutedPrototype.email = "attacker@evil";
    pollutedPrototype.name = "Mallory";

    const token = await mintWithJose({
      ...goodClaims,
      entitlements: ["real"],
      email: "u@x",
      name: "Real",
    });

    expect(await verifyIdentityJwt(token, SECRET, OK)).toEqual({
      subject: "subject-1",
      entitlements: ["real"],
      email: "u@x",
      name: "Real",
    });
  });

  it("does not source a missing alg from Object.prototype", async () => {
    pollutedPrototype.alg = "HS256";
    const signed = await signRawPayload(JSON.stringify(goodClaims));
    const payload = signed.split(".")[1]!;
    const token = `eyJ0eXAiOiJKV1QifQ.${payload}.AAAA`;

    expect(await verifyIdentityJwt(token, SECRET, OK)).toBeNull();
  });
});
