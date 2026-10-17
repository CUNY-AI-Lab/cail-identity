import { describe, expect, it } from "vitest";

import {
  deriveAppSubject,
  isAppSubject,
  isCailSubject,
} from "../src/index.js";

const salt = "local-proof-subject-salt-do-not-use";

describe("stable CAIL app-principal subject", () => {
  it.each([
    ["kale:reference-librarian", salt, "app-f2df9b696a24e25456da81334d1be343"],
    ["kale:other-project", salt, "app-dcec50f23cdbf4d281a40b7fa79ec925"],
    [
      "kale:reference-librarian",
      "another-salt-at-least-32-bytes-long",
      "app-5375378fcf5a70dfdc592598fd89210f",
    ],
  ])("derives the fixed cross-language vector for %s under salt %s", async (appId, subjectSalt, expected) => {
    await expect(deriveAppSubject(appId, subjectSalt)).resolves.toBe(expected);
  });

  it("uses the app id byte-exact — no canonicalization", async () => {
    const lower = await deriveAppSubject("kale:widget", salt);
    const upper = await deriveAppSubject("KALE:WIDGET", salt);
    expect(upper).not.toBe(lower);
  });

  it("produces a canonical app subject disjoint from user subjects", async () => {
    const subject = await deriveAppSubject("kale:reference-librarian", salt);
    expect(isAppSubject(subject)).toBe(true);
    expect(isCailSubject(subject)).toBe(false);
  });

  it.each([
    ["an empty app id", "", salt],
    ["an app id with edge whitespace", "  padded  ", salt],
    ["an app id with a control character", "ctl\u0001id", salt],
    // SAFETY: this deliberately injects a non-string runtime value to exercise
    // the public app-id validation boundary.
    ["a non-string app id", undefined as never, salt],
    ["an empty salt", "kale:widget", ""],
    ["a salt with a control character", "kale:widget", "ctl\u0001salt"],
    ["a 31-byte salt", "kale:widget", "x".repeat(31)],
  ])("rejects %s", async (_name, appId, subjectSalt) => {
    await expect(deriveAppSubject(appId, subjectSalt)).rejects.toThrow(TypeError);
  });

  it.each([
    ["app-" + "0".repeat(32), true],
    ["app-" + "0".repeat(31), false],
    ["app-" + "G".repeat(32), false],
    ["APP-" + "0".repeat(32), false],
    ["cail-" + "0".repeat(32), false],
    [42, false],
    [null, false],
  ])("isAppSubject(%j) is %s", (value, expected) => {
    expect(isAppSubject(value)).toBe(expected);
  });
});
