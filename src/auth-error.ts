import * as z from "zod/mini";

import {
  containsControlCharacter,
  plainRecordFrom,
  stringFrom,
} from "./validation.js";

/** The single production origin that may receive a browser launch. */
export const CAIL_CANONICAL_ORIGIN =
  "https://tools.ailab.gc.cuny.edu" as const;

/** Auth/SSO failure codes currently emitted by the active CAIL fleet. */
export const CAIL_AUTH_ERROR_CODES = Object.freeze([
  "authentication_required",
  "authentication_failed",
  "invalid_credential",
  "session_invalid",
  "admission_required",
  "admission_unavailable",
  "identity_unavailable",
  "identity_verification_misconfigured",
] as const);

export type CailAuthErrorCode = (typeof CAIL_AUTH_ERROR_CODES)[number];

export interface CailAuthError {
  readonly code: CailAuthErrorCode;
  readonly message: string;
  readonly launch?: string;
}

export interface CailAuthErrorEnvelope {
  readonly error: CailAuthError;
}

const LAUNCH_SEGMENT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]*$/;

function isSafeLaunchPath(value: string): boolean {
  if (
    !value.startsWith("/") ||
    value.startsWith("//") ||
    value.includes("\\") ||
    value.includes("?") ||
    value.includes("#") ||
    containsControlCharacter(value)
  ) {
    return false;
  }

  const segments = value.split("/");
  for (let index = 1; index < segments.length; index += 1) {
    const segment = segments[index]!;
    if (segment === "" && index === segments.length - 1) continue;
    if (
      segment === "" ||
      segment === "." ||
      segment === ".." ||
      !LAUNCH_SEGMENT_PATTERN.test(segment)
    ) {
      return false;
    }
  }
  return true;
}

function isSafeCanonicalLaunchUrl(value: string): boolean {
  if (
    !value.startsWith("https://") ||
    value.includes("\\") ||
    value.includes("?") ||
    value.includes("#") ||
    containsControlCharacter(value)
  ) {
    return false;
  }
  const firstPathSlash = value.indexOf("/", "https://".length);
  if (firstPathSlash === -1) return false;
  const authority = value.slice("https://".length, firstPathSlash);
  if (authority !== CAIL_CANONICAL_ORIGIN.slice("https://".length)) {
    return false;
  }
  const rawPath = value.slice(firstPathSlash).split(/[?#]/, 1)[0]!;
  if (!isSafeLaunchPath(rawPath)) return false;
  try {
    const url = new URL(value);
    return (
      url.origin === CAIL_CANONICAL_ORIGIN &&
      url.username === "" &&
      url.password === "" &&
      url.search === "" &&
      url.hash === "" &&
      isSafeLaunchPath(url.pathname)
    );
  } catch {
    return false;
  }
}

/**
 * True only for a same-origin absolute launch or a root-relative launch path.
 * Query strings, fragments, dot segments, backslashes, and protocol-relative
 * URLs are rejected so a parsed launch value cannot become an open redirect.
 */
export function isCailAuthLaunch<Value>(value: Value): value is Value & string {
  const text = stringFrom(value);
  return (
    text !== undefined &&
    (isSafeLaunchPath(text) || isSafeCanonicalLaunchUrl(text))
  );
}

function isSafeMessage(value: string): boolean {
  return value.length > 0 && !containsControlCharacter(value);
}

const ERROR_SCHEMA = z.strictObject({
  code: z.enum(CAIL_AUTH_ERROR_CODES),
  message: z.string().check(z.refine(isSafeMessage)),
  launch: z.optional(z.string().check(z.refine(isCailAuthLaunch))),
});

const ENVELOPE_SCHEMA = z.strictObject({ error: ERROR_SCHEMA });

type MutableCailAuthError = {
  code: CailAuthErrorCode;
  message: string;
  launch?: string;
};

function hasOnlyOwnKeys<Value>(
  value: Value,
  allowed: readonly string[],
  required: readonly string[],
): boolean {
  const record = plainRecordFrom(value);
  if (record === undefined) return false;
  try {
    const names = Object.getOwnPropertyNames(record.owner);
    if (required.some((name) => !names.includes(name))) return false;
    for (const name of names) {
      if (!allowed.includes(name)) return false;
      const descriptor = Object.getOwnPropertyDescriptor(record.owner, name);
      if (descriptor === undefined || !("value" in descriptor)) return false;
    }
    return Object.getOwnPropertySymbols(record.owner).length === 0;
  } catch {
    return false;
  }
}

function freezeEnvelope(value: { error: MutableCailAuthError }): CailAuthErrorEnvelope {
  const error: MutableCailAuthError = {
    code: value.error.code,
    message: value.error.message,
  };
  if (value.error.launch !== undefined) error.launch = value.error.launch;
  return Object.freeze({ error: Object.freeze(error) });
}

/**
 * Parse one nested CAIL auth envelope. The root and nested objects are strict;
 * unknown codes, extra properties, flat legacy shapes, and unsafe launches
 * all return null.
 */
export function parseCailAuthErrorEnvelope<Value>(
  value: Value,
): CailAuthErrorEnvelope | null {
  try {
    const root = plainRecordFrom(value);
    if (root === undefined || !hasOnlyOwnKeys(value, ["error"], ["error"])) {
      return null;
    }
    const nested = root.read("error");
    const nestedRecord = plainRecordFrom(nested);
    if (
      nestedRecord === undefined ||
      !hasOnlyOwnKeys(
        nested,
        ["code", "message", "launch"],
        ["code", "message"],
      )
    ) {
      return null;
    }
    const hasLaunch = nestedRecord.has("launch");
    const launch = hasLaunch ? nestedRecord.read("launch") : undefined;
    if (hasLaunch && launch === undefined) return null;
    const candidateError = {
      code: nestedRecord.read("code"),
      message: nestedRecord.read("message"),
      launch,
    };
    const parsed = ENVELOPE_SCHEMA.safeParse({ error: candidateError });
    if (!parsed.success) return null;
    return freezeEnvelope(parsed.data);
  } catch {
    return null;
  }
}

/** Parse a JSON response body containing one nested CAIL auth envelope. */
export function parseCailAuthErrorJson<Value>(
  value: Value,
): CailAuthErrorEnvelope | null {
  const text = stringFrom(value);
  if (text === undefined) return null;
  try {
    return parseCailAuthErrorEnvelope(JSON.parse(text));
  } catch {
    return null;
  }
}

/**
 * Construct a validated nested auth envelope. This is the only constructor;
 * callers cannot emit a flat or partially validated error through this API.
 */
export function createCailAuthError(
  code: CailAuthErrorCode,
  message: string,
  launch?: string,
): CailAuthErrorEnvelope {
  const error: MutableCailAuthError = {
    code,
    message,
  };
  if (launch !== undefined) error.launch = launch;
  const parsed = parseCailAuthErrorEnvelope({ error });
  if (parsed === null) {
    throw new TypeError("invalid CAIL auth error envelope");
  }
  return parsed;
}

/** Serialize only a validated nested envelope, never a flat compatibility body. */
export function serializeCailAuthError(
  value: CailAuthErrorEnvelope,
): string {
  const parsed = parseCailAuthErrorEnvelope(value);
  if (parsed === null) {
    throw new TypeError("invalid CAIL auth error envelope");
  }
  return JSON.stringify(parsed);
}
