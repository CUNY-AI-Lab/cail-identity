import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  isAppSubject,
  isCailPrincipalSubject,
  isCailSubject,
} from "../src/index.js";

const contract = JSON.parse(
  readFileSync(
    new URL("../contract/principal-v1.json", import.meta.url),
    "utf8",
  ),
) as {
  oneOf: Array<{ pattern: string }>;
  examples: string[];
};

describe("principal-v1 contract", () => {
  it("keeps user and app principal namespaces disjoint", () => {
    const [user, app] = contract.examples;
    expect(isCailSubject(user)).toBe(true);
    expect(isAppSubject(user)).toBe(false);
    expect(isAppSubject(app)).toBe(true);
    expect(isCailSubject(app)).toBe(false);
    expect(contract.oneOf.map((entry) => entry.pattern)).toEqual([
      "^cail-[0-9a-f]{32}$",
      "^app-[0-9a-f]{32}$",
    ]);
  });

  it("rejects log pseudonyms and noncanonical identifiers", () => {
    for (const value of [
      "cail-v1-0123456789abcdef0123456789abcdef",
      "cail-ABCDEF0123456789ABCDEF0123456789",
      "app-abc",
      "user@example.edu",
      "",
      null,
    ]) {
      expect(isCailPrincipalSubject(value)).toBe(false);
    }
  });
});
