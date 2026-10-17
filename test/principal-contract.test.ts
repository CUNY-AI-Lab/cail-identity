import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { isCailPrincipalSubject } from "../src/index.js";

// SAFETY: this checked-in contract fixture is parsed only for its examples
// field, which each test passes to the package.
const contract = JSON.parse(
  readFileSync(
    new URL("../contract/principal-v1.json", import.meta.url),
    "utf8",
  ),
) as { examples: string[] };

describe("principal-v1 contract", () => {
  it.each(contract.examples)("accepts the contract example %s as a principal", (example) => {
    expect(isCailPrincipalSubject(example)).toBe(true);
  });

  it.each([
    "cail-v1-0123456789abcdef0123456789abcdef",
    "cail-ABCDEF0123456789ABCDEF0123456789",
    "app-abc",
    "user@example.edu",
    "",
    null,
  ])("rejects log pseudonym or noncanonical identifier %j", (value) => {
    expect(isCailPrincipalSubject(value)).toBe(false);
  });
});
