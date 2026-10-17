import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  deriveCailOperationalSubject,
  deriveCailSubject,
  isCailSubject,
  type DeriveCailSubjectOptions,
} from "../src/index.js";

const SALT = "local-proof-subject-salt-do-not-use";
const options = {
  issuer: "http://identity:8090/cuny",
  subjectSalt: SALT,
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

// SAFETY: this checked-in contract fixture is parsed only for the vector
// fields asserted by the cross-language contract tests below.
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

describe("subject derivation v2 vectors", () => {
  it.each(vectorContract.vectors)(
    "derives the ownership subject for vector $name",
    async (vector) => {
      await expect(
        deriveCailSubject({
          issuer: vector.issuer,
          oidcSubject: vector.oidcSubject,
          subjectSalt: vectorContract.salt,
        }),
      ).resolves.toBe(vector.ownershipSubject);
    },
  );

  it.each(vectorContract.vectors)(
    "derives the operational subject for vector $name",
    async (vector) => {
      await expect(
        deriveCailOperationalSubject({
          issuer: vector.issuer,
          oidcSubject: vector.oidcSubject,
          operationalSubjectSalt: vectorContract.salt,
        }),
      ).resolves.toBe(vector.operationalSubject);
    },
  );

  it.each(vectorContract.vectors)(
    "frames the Lua canonical subject and material for vector $name",
    (vector) => {
      const output = execFileSync(
        "luajit",
        [luaVectorRunner, vector.issuer, vector.oidcSubject],
        { encoding: "utf8" },
      );
      expect(output.trimEnd().split("\n")).toEqual([
        vector.canonicalSubject,
        vector.ownershipMaterial,
        vector.operationalMaterial,
      ]);
    },
  );
});

describe("stable CAIL subject", () => {
  it.each([
    [
      "ownership",
      (issuer: string, oidcSubject: string) =>
        deriveCailSubject({ issuer, oidcSubject, subjectSalt: SALT }),
    ],
    [
      "operational",
      (issuer: string, oidcSubject: string) =>
        deriveCailOperationalSubject({
          issuer,
          oidcSubject,
          operationalSubjectSalt: SALT,
        }),
    ],
  ])(
    "separates the %s subjects of two inputs that collided under issuer|subject",
    async (_kind, derive) => {
      const left = await derive("https://issuer.example/a", "b|c");
      const right = await derive("https://issuer.example/a|B", "c");
      expect(left).not.toBe(right);
    },
  );

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

  it.each<[string, Partial<DeriveCailSubjectOptions>]>([
    ["a subject that is empty after the realm is removed", { oidcSubject: " @login.cuny.edu " }],
    ["a subject with an interior control character", { oidcSubject: "bo\u0001b" }],
    ["an empty issuer", { issuer: "" }],
    ["an empty salt", { subjectSalt: "" }],
    ["a 31-byte salt", { subjectSalt: "x".repeat(31) }],
  ])("rejects %s", async (_name, over) => {
    await expect(
      deriveCailSubject({ ...options, oidcSubject: "bob", ...over }),
    ).rejects.toThrow(TypeError);
  });

  it("trims a trailing newline like the gate instead of rejecting it", async () => {
    await expect(
      deriveCailSubject({ ...options, oidcSubject: "bob\n" }),
    ).resolves.toBe(await deriveCailSubject({ ...options, oidcSubject: "BOB" }));
  });

  // Canonicalization is ASCII-only, matching the gate's byte-wise LuaJIT
  // implementation. A Unicode-aware toUpperCase would fold ß→SS and ı→I, and
  // a Unicode trim would drop NBSP, merging distinct people.
  it.each([
    ["straße", "strasse"],
    ["bıb", "bib"],
    ["bob ", "bob"],
  ])("keeps %j distinct from %j", async (left, right) => {
    const leftSubject = await deriveCailSubject({ ...options, oidcSubject: left });
    const rightSubject = await deriveCailSubject({ ...options, oidcSubject: right });
    expect(leftSubject).not.toBe(rightSubject);
  });

  it.each([
    ["cail-acdbd45ac152e6d248f1123c831c02c6", true],
    ["cail-ACDBD45AC152E6D248F1123C831C02C6", false],
    ["bob@login.cuny.edu", false],
  ])("isCailSubject(%j) is %s", (value, expected) => {
    expect(isCailSubject(value)).toBe(expected);
  });

  it("snapshots hostile derivation accessors and uses the exact salt bytes validated", async () => {
    const reads = { issuer: 0, oidcSubject: 0, subjectSalt: 0 };
    // SAFETY: the null-prototype object is populated with the exact derivation
    // option accessors immediately below to exercise the snapshot boundary.
    const hostile = Object.create(null) as DeriveCailSubjectOptions;
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
    // SAFETY: Object.keys(values) contains exactly the three derivation option
    // names used by the accessor map below.
    for (const name of Object.keys(values) as Array<keyof typeof values>) {
      Object.defineProperty(hostile, name, {
        enumerable: true,
        get() {
          reads[name] += 1;
          return reads[name] === 1 ? values[name] : later[name];
        },
      });
    }

    await expect(deriveCailSubject(hostile)).resolves.toBe(
      "cail-07c3e42149a128923ef778dcb680b733",
    );
    expect(reads).toEqual({ issuer: 1, oidcSubject: 1, subjectSalt: 1 });
  });
});
