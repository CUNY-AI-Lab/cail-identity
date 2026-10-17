import { describe, expect, it } from "vitest";
import { CAIL_CANONICAL_ISSUER } from "@cuny-ai-lab/cail-identity";

describe("published package entry", () => {
  it("exports the canonical standalone issuer", () => {
    expect(CAIL_CANONICAL_ISSUER).toBe(
      "https://tools.ailab.gc.cuny.edu/cail-sso",
    );
  });
});
