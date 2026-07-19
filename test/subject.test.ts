import { describe, expect, it } from "vitest";

import {
  canonicalizeCunySubject,
  deriveCailSubject,
  isCailSubject,
} from "../src/index.js";

const options = {
  issuer: "http://identity:8090/cuny",
  subjectSalt: "local-proof-subject-salt-do-not-use",
};

describe("stable CAIL subject", () => {
  it("canonicalizes the established CUNY login realm contract", () => {
    expect(canonicalizeCunySubject("  Bob@login.cuny.edu  ")).toBe("BOB");
    expect(canonicalizeCunySubject("opaque-123")).toBe("OPAQUE-123");
  });

  it("matches fixed cross-language HMAC-SHA256 vectors", async () => {
    await expect(
      deriveCailSubject({
        ...options,
        oidcSubject: "bob@LOGIN.CUNY.EDU",
      }),
    ).resolves.toBe("cail-acdbd45ac152e6d248f1123c831c02c6");
    await expect(
      deriveCailSubject({
        ...options,
        oidcSubject: "  Bob@login.cuny.edu  ",
      }),
    ).resolves.toBe("cail-acdbd45ac152e6d248f1123c831c02c6");
    await expect(
      deriveCailSubject({ ...options, oidcSubject: "opaque-123" }),
    ).resolves.toBe("cail-1d2bf35800558380b6988c6f1dee46ae");
  });

  it("namespaces a subject by issuer", async () => {
    const first = await deriveCailSubject({
      ...options,
      oidcSubject: "bob",
    });
    const second = await deriveCailSubject({
      ...options,
      issuer: "https://different.example/oidc",
      oidcSubject: "bob",
    });
    expect(second).not.toBe(first);
  });

  it("rejects empty and control-bearing inputs", async () => {
    expect(() => canonicalizeCunySubject(" @login.cuny.edu ")).toThrow(
      "must not be empty",
    );
    expect(() => canonicalizeCunySubject("bob\n")).toThrow("without controls");
    await expect(
      deriveCailSubject({ ...options, issuer: "", oidcSubject: "bob" }),
    ).rejects.toThrow("issuer");
    await expect(
      deriveCailSubject({
        ...options,
        subjectSalt: "",
        oidcSubject: "bob",
      }),
    ).rejects.toThrow("subjectSalt");
  });

  it("recognizes only the canonical public subject format", () => {
    expect(isCailSubject("cail-acdbd45ac152e6d248f1123c831c02c6")).toBe(true);
    expect(isCailSubject("cail-ACDBD45AC152E6D248F1123C831C02C6")).toBe(false);
    expect(isCailSubject("bob@login.cuny.edu")).toBe(false);
  });
});
