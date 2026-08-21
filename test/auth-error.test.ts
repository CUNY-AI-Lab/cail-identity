import { describe, expect, it } from "vitest";

import {
  CAIL_AUTH_ERROR_CODES,
  CAIL_CANONICAL_ORIGIN,
  createCailAuthError,
  isCailAuthLaunch,
  parseCailAuthErrorEnvelope,
  parseCailAuthErrorJson,
  serializeCailAuthError,
} from "../src/index.js";

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

  it("accepts only the active finite auth code set", () => {
    expect(CAIL_AUTH_ERROR_CODES).toEqual([
      "authentication_required",
      "authentication_failed",
      "invalid_credential",
      "session_invalid",
      "admission_required",
      "admission_unavailable",
      "identity_unavailable",
      "identity_verification_misconfigured",
    ]);
    expect(
      parseCailAuthErrorJson(
        '{"error":{"code":"admission_required","message":"Request access."}}',
      ),
    ).toEqual({
      error: { code: "admission_required", message: "Request access." },
    });
  });

  it("rejects flat, extra, malformed, and unknown fields", () => {
    const invalidBodies = [
      '{"error":"authentication_required"}',
      '{"error":{"code":"authentication_required","message":"Sign in.","extra":true}}',
      '{"error":{"code":"unknown","message":"Sign in."}}',
      '{"error":{"code":"authentication_required"}}',
      '{"error":{"code":"authentication_required","message":""}}',
      '{"error":{"code":"authentication_required","message":"bad\\nmessage"}}',
      '{"error":{"code":"authentication_required","message":"Sign in."},"extra":true}',
      '{"error":{"code":"authentication_required","message":"Sign in.","launch":"https://evil.example/launch"}}',
      '{"error":{"code":"authentication_required","message":"Sign in.","launch":"//evil.example/launch"}}',
      '{"error":{"code":"authentication_required","message":"Sign in.","launch":"/launch/../evil"}}',
      '{"error":{"code":"authentication_required","message":"Sign in.","launch":"/launch/agent-studio?next=https://evil.example"}}',
      '{"error":{"code":"authentication_required","message":"Sign in.","launch":"https://tools.ailab.gc.cuny.edu/launch/agent-studio?next=/"}}',
    ];

    for (const body of invalidBodies) {
      expect(parseCailAuthErrorJson(body)).toBeNull();
    }
    expect(parseCailAuthErrorJson("not-json")).toBeNull();
    expect(parseCailAuthErrorJson(null)).toBeNull();
    expect(parseCailAuthErrorEnvelope({ error: "authentication_required" })).toBeNull();
    expect(
      parseCailAuthErrorEnvelope({
        error: {
          code: "authentication_required",
          message: "Sign in.",
          launch: undefined,
        },
      }),
    ).toBeNull();

    const nonEnumerableRootExtra = {
      error: { code: "authentication_required", message: "Sign in." },
    };
    Object.defineProperty(nonEnumerableRootExtra, "extra", {
      value: true,
      enumerable: false,
    });
    expect(parseCailAuthErrorEnvelope(nonEnumerableRootExtra)).toBeNull();

    const nonEnumerableNestedExtra = {
      error: { code: "authentication_required", message: "Sign in." },
    };
    Object.defineProperty(nonEnumerableNestedExtra.error, "extra", {
      value: true,
      enumerable: false,
    });
    expect(parseCailAuthErrorEnvelope(nonEnumerableNestedExtra)).toBeNull();

    const getterEnvelope = {};
    Object.defineProperty(getterEnvelope, "error", {
      get: () => ({ code: "authentication_required", message: "Sign in." }),
      enumerable: true,
    });
    expect(parseCailAuthErrorEnvelope(getterEnvelope)).toBeNull();
  });

  it("validates relative and canonical-origin launches without redirects", () => {
    const valid = [
      "/",
      "/launch/agent-studio",
      "/site-studio/",
      `${CAIL_CANONICAL_ORIGIN}/model-access`,
    ];
    for (const launch of valid) expect(isCailAuthLaunch(launch)).toBe(true);

    const invalid = [
      "launch/agent-studio",
      "//evil.example/launch",
      "/launch//agent-studio",
      "/launch/./agent-studio",
      "/launch/agent-studio#fragment",
      "/launch/agent-studio?next=/",
      "/launch\\agent-studio",
      `${CAIL_CANONICAL_ORIGIN}.evil.example/launch/agent-studio`,
      `${CAIL_CANONICAL_ORIGIN}:443/launch/agent-studio`,
      "https://TOOLS.AILAB.GC.CUNY.EDU/launch/agent-studio",
      CAIL_CANONICAL_ORIGIN,
      `${CAIL_CANONICAL_ORIGIN}/launch/../agent-studio`,
      `${CAIL_CANONICAL_ORIGIN}/%2e%2e/agent-studio`,
      `${CAIL_CANONICAL_ORIGIN}/launch/agent-studio#fragment`,
      `${CAIL_CANONICAL_ORIGIN}/launch/agent-studio?next=/`,
      `${CAIL_CANONICAL_ORIGIN}/launch/agent-studio?`,
      `${CAIL_CANONICAL_ORIGIN}/launch/agent-studio#`,
      `${CAIL_CANONICAL_ORIGIN}/launch/agent-studio?#`,
      `${CAIL_CANONICAL_ORIGIN}/launch\\agent-studio`,
      `${CAIL_CANONICAL_ORIGIN}/launch/agent\nstudio`,
      `${CAIL_CANONICAL_ORIGIN}/launch `,
    ];
    for (const launch of invalid) expect(isCailAuthLaunch(launch)).toBe(false);
    expect(isCailAuthLaunch(42)).toBe(false);
    expect(isCailAuthLaunch(null)).toBe(false);
  });

  it("fails closed when constructors receive unsafe values", () => {
    expect(() => createCailAuthError("authentication_required", "")).toThrow(
      "invalid CAIL auth error envelope",
    );
    expect(() =>
      createCailAuthError(
        "authentication_required",
        "Sign in.",
        "https://evil.example/launch",
      ),
    ).toThrow("invalid CAIL auth error envelope");
  });
});
