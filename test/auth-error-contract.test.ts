import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  CAIL_AUTH_ERROR_CODES,
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

// SAFETY: this checked-in contract fixture is parsed only for the schema
// fields declared here; each test compares them against package behavior.
const contract = JSON.parse(
  readFileSync(
    new URL("../contract/auth-error-envelope-v1.json", import.meta.url),
    "utf8",
  ),
) as {
  properties: {
    error: {
      required: string[];
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

const ORIGIN = "https://tools.ailab.gc.cuny.edu";
const LAUNCH_PATHS = [
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
  "/launch/agent-studio#",
  "/launch/agent-studio?#",
  "/launch/agent-studio#fragment",
  "/launch\\agent-studio",
  "/%2e%2e/agent-studio",
  "/launch/agent\nstudio",
  "/launch ",
];
const LAUNCH_CANDIDATES = [
  ...LAUNCH_PATHS,
  ...LAUNCH_PATHS.map((path) => `${ORIGIN}${path}`),
  "launch/agent-studio",
  "//evil.example/launch",
  "https://evil.example/launch",
  `${ORIGIN}.evil.example/launch`,
  `${ORIGIN}:443/launch`,
  "https://TOOLS.AILAB.GC.CUNY.EDU/launch",
  "http://tools.ailab.gc.cuny.edu/launch",
  "https://user@tools.ailab.gc.cuny.edu/launch",
];

describe("auth-error-envelope-v1 contract", () => {
  it("exports exactly the contract's code set", () => {
    expect(CAIL_AUTH_ERROR_CODES).toEqual(code.enum);
  });

  it.each(code.enum ?? [])("parses contract code %s", (value) => {
    expect(
      parseCailAuthErrorEnvelope({ error: { code: value, message: "x" } }),
    ).not.toBeNull();
  });

  it.each(contract.examples)("round-trips contract example %j unchanged", (example) => {
    const parsed = parseCailAuthErrorEnvelope(example);
    expect(parsed).toEqual(example);
    expect(JSON.parse(serializeCailAuthError(parsed!))).toEqual(example);
  });

  it("rejects an envelope without error", () => {
    expect(parseCailAuthErrorEnvelope({})).toBeNull();
  });

  it.each(errorSchema.required)("rejects an envelope missing error.%s", (field) => {
    const [example] = contract.examples;
    const error = Object.fromEntries(
      Object.entries(example!.error).filter(([name]) => name !== field),
    );
    expect(parseCailAuthErrorEnvelope({ error })).toBeNull();
  });

  it.each([
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
    "separator ",
  ])("accepts message %j exactly when the contract pattern does", (value) => {
    const accepted =
      parseCailAuthErrorEnvelope({
        error: { code: "authentication_required", message: value },
      }) !== null;
    expect(accepted).toBe(contractMessage(value));
  });

  it.each(LAUNCH_CANDIDATES)("isCailAuthLaunch(%j) agrees with the contract patterns", (value) => {
    expect(isCailAuthLaunch(value)).toBe(contractLaunch(value));
  });

  it.each(LAUNCH_CANDIDATES)("accepts envelope launch %j exactly when the contract patterns do", (value) => {
    const accepted =
      parseCailAuthErrorEnvelope({
        error: {
          code: "authentication_required",
          message: "Sign in.",
          launch: value,
        },
      }) !== null;
    expect(accepted).toBe(contractLaunch(value));
  });

  it.each([42, null])("rejects non-string launch %j", (value) => {
    expect(isCailAuthLaunch(value)).toBe(false);
  });
});
