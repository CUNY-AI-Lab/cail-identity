import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  canonicalizeCunySubject,
  deriveCailOperationalSubject,
  deriveCailSubject,
  isCailSubject,
} from "../src/index.js";

const options = {
  issuer: "http://identity:8090/cuny",
  subjectSalt: "local-proof-subject-salt-do-not-use",
};

interface SubjectVector {
  name: string;
  issuer: string;
  oidcSubject: string;
  canonicalSubject: string;
  ownershipMaterial: string;
  operationalMaterial: string;
  ownershipSubject: string;
  operationalSubject: string;
}

const vectorContract = JSON.parse(
  readFileSync(
    new URL("../contract/subject-derivation-v2.json", import.meta.url),
    "utf8",
  ),
) as {
  salt: string;
  vectors: SubjectVector[];
};
const luaVectorRunner = fileURLToPath(
  new URL("./subject-derivation-v2.lua", import.meta.url),
);

describe("stable CAIL subject", () => {
  it("canonicalizes the established CUNY login realm contract", () => {
    expect(canonicalizeCunySubject("  Bob@login.cuny.edu  ")).toBe("BOB");
    expect(canonicalizeCunySubject("opaque-123")).toBe("OPAQUE-123");
  });

  it("matches the shared TypeScript and Lua v2 derivation vectors", async () => {
    for (const vector of vectorContract.vectors) {
      await expect(
        deriveCailSubject({
          issuer: vector.issuer,
          oidcSubject: vector.oidcSubject,
          subjectSalt: vectorContract.salt,
        }),
        vector.name,
      ).resolves.toBe(vector.ownershipSubject);
      await expect(
        deriveCailOperationalSubject({
          issuer: vector.issuer,
          oidcSubject: vector.oidcSubject,
          operationalSubjectSalt: vectorContract.salt,
        }),
        vector.name,
      ).resolves.toBe(vector.operationalSubject);

      const [canonical, ownershipMaterial, operationalMaterial] = execFileSync(
        "luajit",
        [luaVectorRunner, vector.issuer, vector.oidcSubject],
        { encoding: "utf8" },
      )
        .trimEnd()
        .split("\n");
      expect(canonical, vector.name).toBe(vector.canonicalSubject);
      expect(ownershipMaterial, vector.name).toBe(vector.ownershipMaterial);
      expect(operationalMaterial, vector.name).toBe(
        vector.operationalMaterial,
      );
    }
  });

  it("separates the two accepted pairs that collided under issuer|subject", async () => {
    const [left, right] = vectorContract.vectors.filter((vector) =>
      vector.name.startsWith("former-delimiter-collision"),
    );
    expect(left).toBeDefined();
    expect(right).toBeDefined();
    expect(`${left!.issuer}|${left!.canonicalSubject}`).toBe(
      `${right!.issuer}|${right!.canonicalSubject}`,
    );
    expect(left!.ownershipMaterial).not.toBe(right!.ownershipMaterial);
    expect(left!.operationalMaterial).not.toBe(right!.operationalMaterial);
    expect(left!.ownershipSubject).not.toBe(right!.ownershipSubject);
    expect(left!.operationalSubject).not.toBe(right!.operationalSubject);
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
    // A trailing newline is ASCII whitespace: trimmed like the gate, not rejected.
    expect(canonicalizeCunySubject("bob\n")).toBe("BOB");
    // An interior control character still fails closed.
    expect(() => canonicalizeCunySubject("bo\u0001b")).toThrow(
      "control characters",
    );
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
    await expect(
      deriveCailSubject({
        ...options,
        subjectSalt: "x".repeat(31),
        oidcSubject: "bob",
      }),
    ).rejects.toThrow("32 UTF-8 bytes");
  });

  it("normalizes ASCII-only and never collides distinct non-ASCII subjects", async () => {
    // Canonicalization is ASCII-only, matching the gate's byte-wise LuaJIT
    // implementation. A Unicode-aware toUpperCase would fold these into
    // colliding subjects (ß→SS, ı→I) — merging distinct people. They must
    // stay distinct and pass through un-uppercased.
    expect(canonicalizeCunySubject("straße")).toBe("STRAßE");
    expect(canonicalizeCunySubject("straße")).not.toBe(
      canonicalizeCunySubject("strasse"),
    );
    expect(canonicalizeCunySubject("bıb")).toBe("BıB");
    expect(canonicalizeCunySubject("bıb")).not.toBe(canonicalizeCunySubject("bib"));
    // Non-ASCII whitespace (NBSP) is NOT trimmed — ASCII %s only, like the gate.
    expect(canonicalizeCunySubject("bob\u00a0")).toBe("BOB\u00a0");
    expect(canonicalizeCunySubject("bob\u00a0")).not.toBe(
      canonicalizeCunySubject("bob"),
    );
    // Distinct derived subjects follow from distinct canonical forms.
    const a = await deriveCailSubject({ ...options, oidcSubject: "bıb" });
    const b = await deriveCailSubject({ ...options, oidcSubject: "bib" });
    expect(a).not.toBe(b);
  });

  it("recognizes only the canonical public subject format", () => {
    expect(isCailSubject("cail-acdbd45ac152e6d248f1123c831c02c6")).toBe(true);
    expect(isCailSubject("cail-ACDBD45AC152E6D248F1123C831C02C6")).toBe(false);
    expect(isCailSubject("bob@login.cuny.edu")).toBe(false);
  });

  it("snapshots hostile derivation accessors and uses the exact salt bytes validated", async () => {
    const reads = { issuer: 0, oidcSubject: 0, subjectSalt: 0 };
    const hostile = Object.create(null) as Record<string, unknown>;
    const values = {
      issuer: options.issuer,
      oidcSubject: "bob@LOGIN.CUNY.EDU",
      subjectSalt: options.subjectSalt,
    };
    const later = {
      issuer: "https://different.example/",
      oidcSubject: "mallory",
      subjectSalt: "short",
    };
    for (const name of Object.keys(values) as Array<keyof typeof values>) {
      Object.defineProperty(hostile, name, {
        enumerable: true,
        get() {
          reads[name] += 1;
          return reads[name] === 1 ? values[name] : later[name];
        },
      });
    }

    await expect(
      deriveCailSubject(hostile as unknown as Parameters<typeof deriveCailSubject>[0]),
    ).resolves.toBe("cail-07c3e42149a128923ef778dcb680b733");
    expect(reads).toEqual({ issuer: 1, oidcSubject: 1, subjectSalt: 1 });
  });
});
