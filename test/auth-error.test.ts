import { describe, expect, it } from "vitest";

import {
  createCailAuthError,
  parseCailAuthErrorEnvelope,
  parseCailAuthErrorJson,
  serializeCailAuthError,
} from "../src/index.js";

const VALID_ERROR = { code: "authentication_required", message: "Sign in." };

const hiddenRootExtra = { error: { ...VALID_ERROR } };
Object.defineProperty(hiddenRootExtra, "extra", { value: true, enumerable: false });

const hiddenNestedExtra = { error: { ...VALID_ERROR } };
Object.defineProperty(hiddenNestedExtra.error, "extra", {
  value: true,
  enumerable: false,
});

describe("CAIL auth error envelope", () => {
  it("constructs and serializes the canonical nested shape", () => {
    const envelope = createCailAuthError(
      "authentication_required",
      "Sign in to continue.",
      "/launch/agent-studio",
    );

    expect(envelope).toEqual({
      error: {
        code: "authentication_required",
        message: "Sign in to continue.",
        launch: "/launch/agent-studio",
      },
    });
    expect(serializeCailAuthError(envelope)).toBe(
      '{"error":{"code":"authentication_required","message":"Sign in to continue.","launch":"/launch/agent-studio"}}',
    );
    expect(Object.isFrozen(envelope)).toBe(true);
    expect(Object.isFrozen(envelope.error)).toBe(true);
  });

  it("parses a code-only envelope without a launch", () => {
    expect(
      parseCailAuthErrorJson(
        '{"error":{"code":"admission_required","message":"Request access."}}',
      ),
    ).toEqual({
      error: { code: "admission_required", message: "Request access." },
    });
  });

  it.each([
    '{"error":"authentication_required"}',
    '{"error":{"code":"authentication_required","message":"Sign in.","extra":true}}',
    '{"error":{"code":"unknown","message":"Sign in."}}',
    '{"error":{"code":"authentication_required"}}',
    '{"error":{"code":"authentication_required","message":""}}',
    '{"error":{"code":"authentication_required","message":"bad\\nmessage"}}',
    '{"error":{"code":"authentication_required","message":"Sign in."},"extra":true}',
    "not-json",
    null,
  ])("rejects body %j", (body) => {
    expect(parseCailAuthErrorJson(body)).toBeNull();
  });

  it("rejects an explicitly undefined launch", () => {
    expect(
      parseCailAuthErrorEnvelope({ error: { ...VALID_ERROR, launch: undefined } }),
    ).toBeNull();
  });

  it.each([
    ["root", hiddenRootExtra],
    ["error", hiddenNestedExtra],
  ])("rejects a non-enumerable extra property on the %s object", (_level, envelope) => {
    expect(parseCailAuthErrorEnvelope(envelope)).toBeNull();
  });

  it("rejects an accessor-backed error property", () => {
    const envelope = {};
    Object.defineProperty(envelope, "error", {
      get: () => ({ ...VALID_ERROR }),
      enumerable: true,
    });
    expect(parseCailAuthErrorEnvelope(envelope)).toBeNull();
  });

  it.each([
    ["an empty message", "", undefined],
    ["an off-origin launch", "Sign in.", "https://evil.example/launch"],
  ])("refuses to construct an envelope with %s", (_name, message, launch) => {
    expect(() =>
      createCailAuthError("authentication_required", message, launch),
    ).toThrow(TypeError);
  });
});
