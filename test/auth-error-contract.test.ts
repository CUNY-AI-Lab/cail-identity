import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  CAIL_AUTH_ERROR_CODES,
  createCailAuthError,
  isCailAuthLaunch,
  parseCailAuthErrorEnvelope,
  serializeCailAuthError,
} from "../src/index.js";

interface StringSchema {
  minLength?: number;
  pattern?: string;
  enum?: string[];
  oneOf?: Array<{ pattern: string }>;
}

interface ObjectSchema {
  required: string[];
  additionalProperties: boolean;
}

// SAFETY: this checked-in contract fixture is parsed only for the schema
// fields declared here; each test compares them against package behavior.
const contract = JSON.parse(
  readFileSync(
    new URL("../contract/auth-error-envelope-v1.json", import.meta.url),
    "utf8",
  ),
) as ObjectSchema & {
  properties: {
    error: ObjectSchema & {
      properties: {
        code: StringSchema;
        message: StringSchema;
        launch: StringSchema;
      };
    };
  };
  examples: Array<{ error: { code: string; message: string; launch?: string } }>;
};

const errorSchema = contract.properties.error;
const { code, message, launch } = errorSchema.properties;

function contractMessage(value: string): boolean {
  return (
    value.length >= (message.minLength ?? 0) &&
    new RegExp(message.pattern ?? "", "u").test(value)
  );
}

function contractLaunch(value: string): boolean {
  const matches = (launch.oneOf ?? []).filter((branch) =>
    new RegExp(branch.pattern, "u").test(value),
  );
  return matches.length === 1;
}

describe("auth-error-envelope-v1 contract", () => {
  it("defines exactly the code set the package accepts", () => {
    expect(CAIL_AUTH_ERROR_CODES).toEqual(code.enum);
    for (const value of code.enum ?? []) {
      expect(
        parseCailAuthErrorEnvelope({ error: { code: value, message: "x" } }),
        value,
      ).not.toBeNull();
    }
  });

  it("produces every contract code in the contract shape", () => {
    const allowedError = Object.keys(errorSchema.properties);
    for (const value of CAIL_AUTH_ERROR_CODES) {
      const body = JSON.parse(
        serializeCailAuthError(createCailAuthError(value, "Sign in.", "/launch")),
      );
      expect(Object.keys(body)).toEqual(contract.required);
      for (const field of errorSchema.required) {
        expect(body.error, `${value}.${field}`).toHaveProperty(field);
      }
      for (const field of Object.keys(body.error)) {
        expect(allowedError, `${value}.${field}`).toContain(field);
      }
      expect(code.enum).toContain(body.error.code);
      expect(contractMessage(body.error.message)).toBe(true);
      expect(contractLaunch(body.error.launch)).toBe(true);
    }
  });

  it("round-trips each contract example unchanged", () => {
    for (const example of contract.examples) {
      const parsed = parseCailAuthErrorEnvelope(example);
      expect(parsed).toEqual(example);
      expect(JSON.parse(serializeCailAuthError(parsed!))).toEqual(example);
    }
  });

  it("rejects a missing required field or an undeclared field at each level", () => {
    const [example] = contract.examples;
    const base = { code: example!.error.code, message: example!.error.message };
    for (const field of errorSchema.required) {
      const error = Object.fromEntries(
        Object.entries(base).filter(([name]) => name !== field),
      );
      expect(parseCailAuthErrorEnvelope({ error }), field).toBeNull();
    }
    expect(parseCailAuthErrorEnvelope({})).toBeNull();
    expect(contract.additionalProperties).toBe(false);
    expect(errorSchema.additionalProperties).toBe(false);
    expect(parseCailAuthErrorEnvelope({ error: base, extra: "x" })).toBeNull();
    expect(
      parseCailAuthErrorEnvelope({ error: { ...base, extra: "x" } }),
    ).toBeNull();
  });

  it("accepts exactly the messages the contract pattern accepts", () => {
    const candidates = [
      "Sign in to continue.",
      "",
      " ",
      "line\nbreak",
      "tab\there",
      "nul\u0000",
      "unit\u001f",
      "del\u007f",
      "c1\u0085",
      "Ünïcode ✓",
      "separator\u2028",
    ];
    for (const value of candidates) {
      const accepted =
        parseCailAuthErrorEnvelope({
          error: { code: "authentication_required", message: value },
        }) !== null;
      expect(accepted, JSON.stringify(value)).toBe(contractMessage(value));
    }
  });

  it("accepts exactly the launches the contract patterns accept", () => {
    const origin = "https://tools.ailab.gc.cuny.edu";
    const paths = [
      "",
      "/",
      "/launch/agent-studio",
      "/site-studio/",
      "/a..b/c_d~e",
      "/launch//agent-studio",
      "/launch/./agent-studio",
      "/launch/../agent-studio",
      "/.hidden",
      "/-dash",
      "/launch/agent-studio?next=/",
      "/launch/agent-studio?",
      "/launch/agent-studio#fragment",
      "/launch\\agent-studio",
      "/%2e%2e/agent-studio",
      "/launch/agent\nstudio",
      "/launch ",
    ];
    const candidates = [
      ...paths,
      ...paths.map((path) => `${origin}${path}`),
      "launch/agent-studio",
      "//evil.example/launch",
      "https://evil.example/launch",
      `${origin}.evil.example/launch`,
      `${origin}:443/launch`,
      "https://TOOLS.AILAB.GC.CUNY.EDU/launch",
      "http://tools.ailab.gc.cuny.edu/launch",
      "https://user@tools.ailab.gc.cuny.edu/launch",
    ];
    for (const value of candidates) {
      expect(isCailAuthLaunch(value), JSON.stringify(value)).toBe(
        contractLaunch(value),
      );
      const accepted =
        parseCailAuthErrorEnvelope({
          error: {
            code: "authentication_required",
            message: "Sign in.",
            launch: value,
          },
        }) !== null;
      expect(accepted, JSON.stringify(value)).toBe(contractLaunch(value));
    }
  });
});
