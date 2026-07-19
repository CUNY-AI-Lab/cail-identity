import { describe, expect, it } from "vitest";

import {
  APP_SUBJECT_PATTERN,
  deriveAppSubject,
  isAppSubject,
  isCailSubject,
} from "../src/index.js";

const salt = "local-proof-subject-salt-do-not-use";

describe("stable CAIL app-principal subject", () => {
  it("matches fixed cross-language HMAC-SHA256 vectors", async () => {
    await expect(
      deriveAppSubject("kale:reference-librarian", salt),
    ).resolves.toBe("app-f2df9b696a24e25456da81334d1be343");
    await expect(deriveAppSubject("kale:other-project", salt)).resolves.toBe(
      "app-dcec50f23cdbf4d281a40b7fa79ec925",
    );
  });

  it("is stable for the same app id and distinct across ids and salts", async () => {
    const first = await deriveAppSubject("kale:reference-librarian", salt);
    const again = await deriveAppSubject("kale:reference-librarian", salt);
    expect(again).toBe(first);
    await expect(deriveAppSubject("kale:other-project", salt)).resolves.not.toBe(
      first,
    );
    await expect(
      deriveAppSubject("kale:reference-librarian", "another-salt"),
    ).resolves.toBe("app-eda0260326501a46c042e4f6281ed412");
  });

  it("uses the app id byte-exact — no canonicalization", async () => {
    const lower = await deriveAppSubject("kale:widget", salt);
    const upper = await deriveAppSubject("KALE:WIDGET", salt);
    expect(upper).not.toBe(lower);
  });

  it("produces subjects the app pattern accepts and the user pattern rejects", async () => {
    const subject = await deriveAppSubject("kale:reference-librarian", salt);
    expect(APP_SUBJECT_PATTERN.test(subject)).toBe(true);
    expect(isAppSubject(subject)).toBe(true);
    expect(isCailSubject(subject)).toBe(false);
  });

  it("rejects invalid app ids and salts", async () => {
    await expect(deriveAppSubject("", salt)).rejects.toThrow("appId");
    await expect(deriveAppSubject("  padded  ", salt)).rejects.toThrow("appId");
    await expect(deriveAppSubject("ctl\u0001id", salt)).rejects.toThrow(
      "appId",
    );
    await expect(
      deriveAppSubject(undefined as unknown as string, salt),
    ).rejects.toThrow("appId");
    await expect(deriveAppSubject("kale:widget", "")).rejects.toThrow(
      "subjectSalt",
    );
    await expect(
      deriveAppSubject("kale:widget", "ctl\u0001salt"),
    ).rejects.toThrow("subjectSalt");
  });

  it("isAppSubject accepts only the canonical representation", () => {
    expect(isAppSubject("app-" + "0".repeat(32))).toBe(true);
    expect(isAppSubject("app-" + "0".repeat(31))).toBe(false);
    expect(isAppSubject("app-" + "G".repeat(32))).toBe(false);
    expect(isAppSubject("APP-" + "0".repeat(32))).toBe(false);
    expect(isAppSubject("cail-" + "0".repeat(32))).toBe(false);
    expect(isAppSubject(42)).toBe(false);
    expect(isAppSubject(null)).toBe(false);
  });
});
