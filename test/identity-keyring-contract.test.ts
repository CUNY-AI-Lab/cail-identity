import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { readIdentityKeyring } from "../src/index.js";

interface LegSchema {
  minLength: number;
  maxLength: number;
  pattern: string;
}

type Leg = "app_jwt" | "gateway_jwt";

// SAFETY: this checked-in contract fixture is parsed only for the schema
// fields declared here; each test compares them against keyring behavior.
const contract = JSON.parse(
  readFileSync(
    new URL("../contract/identity-keyring-v1.json", import.meta.url),
    "utf8",
  ),
) as {
  properties: Record<Leg, LegSchema>;
  examples: Array<Record<Leg, string>>;
};

const [example] = contract.examples;

const HEADER = {
  app_jwt: "x-cail-identity-jwt",
  gateway_jwt: "x-cail-gateway-identity-jwt",
} as const satisfies Record<Leg, string>;
const OTHER_LEG = {
  app_jwt: "gateway_jwt",
  gateway_jwt: "app_jwt",
} as const satisfies Record<Leg, Leg>;

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

function candidatesFor(leg: Leg) {
  const { maxLength } = contract.properties[leg];
  const rows: Array<[string, string]> = [
    ["example token", example!.app_jwt],
    ["empty", ""],
    ["two segments", "a.b"],
    ["three segments", "a.b.c"],
    ["four segments", "a.b.c.d"],
    ["an empty segment", "a..c"],
    ["base64 padding", "a.b.c="],
    ["a non-base64url character", "a+b.c.d"],
    ["trailing whitespace", "a.b.c "],
    ["two comma-joined tokens", `${example!.app_jwt},${example!.app_jwt}`],
    ["maximum length", compactOfLength(maxLength)],
    ["maximum length plus one", compactOfLength(maxLength + 1)],
  ];
  return rows.map(([name, value]) => ({ leg, name, value }));
}

const CANDIDATES = [...candidatesFor("app_jwt"), ...candidatesFor("gateway_jwt")];

describe("identity-keyring-v1 contract", () => {
  it.each(CANDIDATES)(
    "reads a $leg leg with $name exactly when the contract accepts it",
    ({ leg, value }) => {
      const headers = new Headers({
        [HEADER[OTHER_LEG[leg]]]: example![OTHER_LEG[leg]],
      });
      headers.set(HEADER[leg], value);
      const accepted = readIdentityKeyring(headers) !== null;
      // Headers trims surrounding whitespace, so compare what was delivered.
      expect(accepted).toBe(
        contractAccepts(contract.properties[leg], headers.get(HEADER[leg]) ?? ""),
      );
    },
  );
});
