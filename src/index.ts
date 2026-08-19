/**
 * @cuny-ai-lab/cail-identity — the CAIL identity-JWT verifier.
 *
 * Pure Web Crypto helpers for the stable CAIL subject and gateway-signed
 * RS256 CAIL identity JWTs.
 *
 * Design contract (see README):
 *   - JOSE/JWT protocol machinery is delegated to `jose`, which uses the same
 *     Web Crypto APIs across Cloudflare Workers, browsers, Bun, and Node >=20.
 *   - Each algorithm is PINNED in code; the token never chooses it.
 *   - Verification key material is passed in — never stored, never logged.
 *   - Invalid tokens fail closed to `null` without revealing a failure reason.
 *     Configuration is loaded separately and remains an owned operator error.
 *   - A verified token must contain the stable pseudonymous CAIL subject.
 *   - Exact `cail:gateway` tokens use the same identity-only claim shape as
 *     every other audience; Registry/Gateway owns access policy separately.
 *   - Subject derivation is explicit and intended only for a trusted CUNY
 *     authentication boundary, never for user-controlled request data.
 */

import { base64url, importJWK, jwtVerify } from "jose";

import {
  numberFrom,
  plainRecordFrom,
  stringFrom,
  unknownArrayFrom,
} from "./validation.js";

export interface CailIdentity {
  subject: string;
  /** Separately keyed pseudonym for privacy-bounded operational events. */
  operationalSubject?: string;
  email?: string;
  name?: string;
  entitlements: string[];
}

/** Stable pseudonymous identifier shared across CAIL applications. */
const CAIL_SUBJECT_PATTERN = /^cail-[0-9a-f]{32}$/;

/** True only for the canonical stable CAIL subject representation. */
export function isCailSubject<Value>(value: Value): value is Value & string {
  const text = stringFrom(value);
  return text !== undefined && CAIL_SUBJECT_PATTERN.test(text);
}

const CUNY_LOGIN_REALM = "@LOGIN.CUNY.EDU";
function containsControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}
// ASCII whitespace only — the exact set LuaJIT's `%s` pattern trims in the gate
// (space, tab, newline, vertical tab, form feed, carriage return).
const ASCII_WHITESPACE = /^[ \t\n\v\f\r]+|[ \t\n\v\f\r]+$/g;
const ASCII_WHITESPACE_CHARACTER = /[ \t\n\v\f\r]/;
const encoder = new TextEncoder();

function snapshotOwnProperty<Value>(value: Value, key: string) {
  const record = plainRecordFrom(value);
  return record !== undefined && record.has(key) ? record.read(key) : undefined;
}

function snapshotSubjectSalt<Value>(
  value: Value,
  optionName: string,
): Uint8Array<ArrayBuffer> {
  const text = stringFrom(value);
  const bytes = text === undefined ? null : encoder.encode(text);
  if (
    text === undefined ||
    containsControlCharacter(text) ||
    bytes === null ||
    bytes.byteLength < 32
  ) {
    throw new TypeError(
      `${optionName} must contain at least 32 UTF-8 bytes without controls.`,
    );
  }
  return bytes;
}

interface SubjectDerivationSnapshot {
  issuer: string;
  canonicalSubject: string;
  saltBytes: Uint8Array<ArrayBuffer>;
}

function snapshotSubjectDerivationOptions<Value>(
  options: Value,
  saltOptionName: "subjectSalt" | "operationalSubjectSalt",
): SubjectDerivationSnapshot {
  let issuer: string | undefined;
  let oidcSubject: string | undefined;
  let salt: string | undefined;
  try {
    const record = plainRecordFrom(options);
    if (record === undefined) {
      throw new TypeError("options must be an object.");
    }
    issuer = stringFrom(record.read("issuer"));
    oidcSubject = stringFrom(record.read("oidcSubject"));
    salt = stringFrom(record.read(saltOptionName));
  } catch {
    throw new TypeError("subject derivation options could not be read.");
  }

  if (
    issuer === undefined ||
    issuer === "" ||
    containsControlCharacter(issuer)
  ) {
    throw new TypeError("issuer must be a non-empty string without controls.");
  }

  const saltBytes = snapshotSubjectSalt(salt, saltOptionName);
  if (oidcSubject === undefined) {
    throw new TypeError("CUNY OIDC subject must be a string.");
  }
  const canonicalSubject = canonicalizeCunySubject(oidcSubject);
  return { issuer, canonicalSubject, saltBytes };
}

const OWNERSHIP_SUBJECT_DOMAIN = "cail-identity/ownership-subject:v2";
const OPERATIONAL_SUBJECT_DOMAIN = "cail-identity/operational-subject:v2";

/**
 * Injectively frame two UTF-8 strings for HMAC.
 *
 * Each field is preceded by its UTF-8 byte length, so no value can be parsed
 * as part of an adjacent field. The fixed, versioned domain separates
 * ownership and operational pseudonyms.
 */
function encodeSubjectHmacInput(
  domain: string,
  issuer: string,
  canonicalSubject: string,
): Uint8Array<ArrayBuffer> {
  const issuerLength = encoder.encode(issuer).byteLength;
  const subjectLength = encoder.encode(canonicalSubject).byteLength;
  return encoder.encode(
    `${domain}:${issuerLength}:${issuer}${subjectLength}:${canonicalSubject}`,
  );
}

/**
 * Canonicalize the trusted CUNY OIDC subject used as pseudonym input.
 *
 * OIDC Core defines `sub` as a case-sensitive opaque string; a compliant RP
 * compares it byte-for-byte and never normalizes. CAIL normalizes for ONE
 * documented reason: CUNYLogin is non-compliant and emits the same person as
 * two forms (`BOB` and `bob@login.cuny.edu`). So we normalize exactly and only
 * that quirk — ASCII whitespace trim, ASCII-only uppercase, one trailing
 * `@LOGIN.CUNY.EDU` realm removed — and leave everything else opaque.
 *
 * ASCII-only is load-bearing: accepted inputs must produce byte-identical
 * output to the gate's LuaJIT `canonicalize_sub` (byte-wise `:upper()` and
 * `%s`). A
 * Unicode-aware `toUpperCase()`/`trim()` would (a) diverge from the gate on
 * non-ASCII input and (b) *collide distinct people* — `ß`→`SS`, dotless `ı`→`I`,
 * NBSP trimming — a merge far beyond the realm quirk. CUNY subjects are ASCII,
 * so no real subject changes. It does not authenticate the value.
 */
function canonicalizeCunySubject(subject: string): string {
  // Trim edge ASCII whitespace first (a trailing newline is trimmed, as the
  // gate does), then fail closed on any interior control character.
  const trimmed = subject.replace(ASCII_WHITESPACE, "");
  if (containsControlCharacter(trimmed)) {
    throw new TypeError("CUNY OIDC subject must not contain control characters.");
  }
  let canonical = trimmed.replace(/[a-z]/g, (ch) => ch.toUpperCase());
  if (canonical.endsWith(CUNY_LOGIN_REALM)) {
    canonical = canonical.slice(0, -CUNY_LOGIN_REALM.length);
  }
  if (canonical === "") {
    throw new TypeError("CUNY OIDC subject must not be empty.");
  }
  return canonical;
}

export interface DeriveCailSubjectOptions {
  /** Exact trusted OIDC issuer; it namespaces otherwise identical subjects. */
  issuer: string;
  /** Subject returned by the trusted CUNY OIDC provider. */
  oidcSubject: string;
  /** Secret stable salt, supplied only at the identity/authentication boundary. */
  subjectSalt: string;
}

function bytesToHex(bytes: Uint8Array): string {
  let result = "";
  for (const byte of bytes) result += byte.toString(16).padStart(2, "0");
  return result;
}

/**
 * Derive the established stable pseudonymous CAIL subject.
 *
 * `cail-` + the first 32 hexadecimal characters of HMAC-SHA256 over the
 * versioned, UTF-8 byte-length-prefixed ownership-subject material.
 */
export async function deriveCailSubject(
  options: DeriveCailSubjectOptions,
): Promise<string> {
  const { issuer, canonicalSubject, saltBytes } =
    snapshotSubjectDerivationOptions(options, "subjectSalt");
  const key = await crypto.subtle.importKey(
    "raw",
    saltBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(
    await crypto.subtle.sign(
      "HMAC",
      key,
      encodeSubjectHmacInput(
        OWNERSHIP_SUBJECT_DOMAIN,
        issuer,
        canonicalSubject,
      ),
    ),
  );
  return `cail-${bytesToHex(digest).slice(0, 32)}`;
}

/**
 * Stable pseudonymous app-principal identifier (ADR-0007).
 *
 * App principals are headless applications with their own spend partition.
 * The `app-` prefix is disjoint from the user `cail-` prefix by construction,
 * so an app subject can never collide with a user subject in a spend
 * partition, an audit row, or a workspace key.
 */
const APP_SUBJECT_PATTERN = /^app-[0-9a-f]{32}$/;

/** True only for the canonical stable CAIL app-principal subject. */
export function isAppSubject<Value>(value: Value): value is Value & string {
  const text = stringFrom(value);
  return text !== undefined && APP_SUBJECT_PATTERN.test(text);
}

/**
 * True for a canonical user or application principal subject.
 *
 * This helper validates identifiers only. It does not authenticate a caller;
 * services still obtain user subjects from a verified identity JWT and app
 * subjects from their trusted control plane.
 */
export function isCailPrincipalSubject<Value>(
  value: Value,
): value is Value & string {
  return isCailSubject(value) || isAppSubject(value);
}

const CAIL_OPERATIONAL_SUBJECT_PATTERN = /^cail-v1-[0-9a-f]{32}$/;

export function isCailOperationalSubject<Value>(
  value: Value,
): value is Value & string {
  const text = stringFrom(value);
  return text !== undefined && CAIL_OPERATIONAL_SUBJECT_PATTERN.test(text);
}

export interface DeriveCailOperationalSubjectOptions {
  issuer: string;
  oidcSubject: string;
  /** A dedicated secret; do not reuse the ownership-subject salt. */
  operationalSubjectSalt: string;
}

/**
 * Derive the separately keyed pseudonym carried as the identity JWT `log_sub`
 * claim and used only for operational events.
 */
export async function deriveCailOperationalSubject(
  options: DeriveCailOperationalSubjectOptions,
): Promise<string> {
  const { issuer, canonicalSubject, saltBytes } =
    snapshotSubjectDerivationOptions(options, "operationalSubjectSalt");
  const key = await crypto.subtle.importKey(
    "raw",
    saltBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(
    await crypto.subtle.sign(
      "HMAC",
      key,
      encodeSubjectHmacInput(
        OPERATIONAL_SUBJECT_DOMAIN,
        issuer,
        canonicalSubject,
      ),
    ),
  );
  return `cail-v1-${bytesToHex(digest).slice(0, 32)}`;
}

/**
 * Derive the stable pseudonymous CAIL app-principal subject (ADR-0007).
 *
 * `app-` + the first 32 hexadecimal characters of
 * HMAC-SHA256(subjectSalt, `app|${appId}`).
 *
 * The same HMAC construction as the user subject, namespaced by the literal
 * `app|` domain-separation prefix and the disjoint `app-` output prefix. The
 * app id is a stable control-plane identifier chosen by a trusted issuing
 * service (never user-controlled request data) and is used byte-exact — no
 * canonicalization, because there is no upstream-IdP quirk to absorb.
 */
export async function deriveAppSubject(
  appId: string,
  subjectSalt: string,
): Promise<string> {
  const appIdText = stringFrom(appId);
  if (
    appIdText === undefined ||
    appIdText === "" ||
    containsControlCharacter(appIdText) ||
    appIdText.replace(ASCII_WHITESPACE, "") !== appIdText
  ) {
    throw new TypeError(
      "appId must be a non-empty string without control characters or edge whitespace.",
    );
  }
  const saltBytes = snapshotSubjectSalt(subjectSalt, "subjectSalt");

  const key = await crypto.subtle.importKey(
    "raw",
    saltBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, encoder.encode(`app|${appIdText}`)),
  );
  return `app-${bytesToHex(digest).slice(0, 32)}`;
}

/** Canonical issuer for every standalone CAIL environment. */
export const CAIL_CANONICAL_ISSUER =
  "https://cail-doorway.ailab-452.workers.dev/cail-sso";

// fatal:true — RFC 7519 §7.2 / RFC 8725 §3.7 require the header and payload
// to be valid UTF-8 JSON. The default lenient decoder would smuggle invalid
// bytes through as U+FFFD instead of rejecting; fatal mode throws inside the
// existing try/catch, so malformed bytes fail closed to null.
const decoder = new TextDecoder("utf-8", { fatal: true });

type JsonValue = null | boolean | number | string | JsonValue[] | JsonRecord;
type JsonRecord = { [key: string]: JsonValue };

function isPlainObject<Value>(value: Value): value is Value & JsonRecord {
  return plainRecordFrom(value) !== undefined;
}

function ownProp<Value>(obj: Value, key: string) {
  return snapshotOwnProperty(obj, key);
}

function isFiniteNumber<Value>(value: Value): value is Value & number {
  const number = numberFrom(value);
  return number !== undefined && Number.isFinite(number);
}

interface InspectedJwt {
  header: JsonRecord;
  payload: JsonRecord;
}

const MAX_CLOCK_TOLERANCE_SECONDS = 300;
const MAX_DATE_SECONDS = 8_640_000_000_000;
const MIN_RSA_MODULUS_BITS = 2048;
// JSON root is depth 0; each object member or array index adds one. Values at
// depth 65 are malformed. This bound is checked iteratively so it does not
// depend on the JavaScript engine's call stack.
const MAX_JWKS_JSON_DEPTH = 64;

function isCanonicalBase64url<Value>(value: Value): value is Value & string {
  const text = stringFrom(value);
  if (text === undefined || text === "") return false;
  if (!/^[A-Za-z0-9_-]+$/.test(text)) return false;
  try {
    return base64url.encode(base64url.decode(text)) === text;
  } catch {
    return false;
  }
}

function decodeCanonicalBase64urlUInt<Value>(value: Value): Uint8Array | null {
  if (!isCanonicalBase64url(value)) return null;
  try {
    const bytes = base64url.decode(value);
    // RFC 7518 Base64urlUInt values use the minimum number of octets.
    return bytes.length > 0 && bytes[0] !== 0 ? bytes : null;
  } catch {
    return null;
  }
}

function hasEligibleRsaPublicNumbers(
  modulus: Uint8Array,
  exponentBytes: Uint8Array,
): boolean {
  const modulusBits =
    (modulus.length - 1) * 8 + (32 - Math.clz32(modulus[0]!));
  if (
    modulusBits < MIN_RSA_MODULUS_BITS ||
    (modulus[modulus.length - 1]! & 1) === 0
  ) {
    return false;
  }

  let exponent = 0;
  for (const byte of exponentBytes) {
    if (
      exponent >
      Math.floor((Number.MAX_SAFE_INTEGER - byte) / 256)
    ) {
      return false;
    }
    exponent = exponent * 256 + byte;
  }
  return exponent >= 3 && exponent % 2 === 1;
}

function parseJsonRecord(text: string): JsonRecord | null {
  try {
    const parsed = JSON.parse(text);
    const record = plainRecordFrom(parsed);
    if (record === undefined) return null;
    // SAFETY: JSON.parse produced a plain object and plainRecordFrom rejected
    // arrays, null, functions, and class instances at this boundary.
    return record.owner as JsonRecord;
  } catch {
    return null;
  }
}

function inspectCailJwt(token: string): InspectedJwt | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const decoded: Uint8Array[] = [];
  try {
    for (const segment of parts) {
      if (!isCanonicalBase64url(segment)) return null;
      decoded.push(base64url.decode(segment));
    }

    const header = parseJsonRecord(decoder.decode(decoded[0]!));
    const payload = parseJsonRecord(decoder.decode(decoded[1]!));
    if (header === null || payload === null) return null;
    if (ownProp(header, "alg") !== "RS256") return null;
    const kid = stringFrom(ownProp(header, "kid"));
    if (kid === undefined || kid === "") return null;
    if (Object.hasOwn(header, "crit")) return null;
    const b64 = ownProp(header, "b64");
    if (b64 !== undefined && b64 !== true) return null;

    return { header, payload };
  } catch {
    return null;
  }
}

function snapshotStringArray<Value>(value: Value): string[] | null {
  try {
    const array = unknownArrayFrom(value);
    if (array === undefined || array.length < 1) return null;
    const snapshot: string[] = [];
    for (let index = 0; index < array.length; index += 1) {
      const item = stringFrom(array[index]);
      if (item === undefined || item === "") return null;
      snapshot.push(item);
    }
    return snapshot;
  } catch {
    return null;
  }
}

function hasExactAudience<Value>(value: Value, expected: string): boolean {
  const text = stringFrom(value);
  return text !== undefined && text !== "" && text === expected;
}

const PRIVATE_JWK_PARAMETERS = [
  "d",
  "p",
  "q",
  "dp",
  "dq",
  "qi",
  "oth",
  "k",
] as const;

function containsPrivateJwkMaterial(value: JsonRecord): boolean {
  return PRIVATE_JWK_PARAMETERS.some((name) => Object.hasOwn(value, name));
}

interface EligibleRsaVerificationJwk {
  key: JsonRecord;
  kid: string;
}

function snapshotRsaVerificationJwk(
  value: JsonRecord,
): EligibleRsaVerificationJwk | null {
  const kid = stringFrom(ownProp(value, "kid"));
  if (
    ownProp(value, "kty") !== "RSA" ||
    kid === undefined ||
    kid === ""
  ) {
    return null;
  }

  const alg = ownProp(value, "alg");
  if (alg !== undefined && alg !== "RS256") return null;
  const use = ownProp(value, "use");
  if (use !== undefined && use !== "sig") return null;
  const keyOps = ownProp(value, "key_ops");
  if (keyOps !== undefined) {
    const keyOpsSnapshot = snapshotStringArray(keyOps);
    if (
      keyOpsSnapshot === null ||
      new Set(keyOpsSnapshot).size !== keyOpsSnapshot.length ||
      !keyOpsSnapshot.includes("verify")
    ) {
      return null;
    }
  }
  if (containsPrivateJwkMaterial(value)) return null;

  const modulus = decodeCanonicalBase64urlUInt(ownProp(value, "n"));
  const exponent = decodeCanonicalBase64urlUInt(ownProp(value, "e"));
  if (
    modulus === null ||
    exponent === null ||
    !hasEligibleRsaPublicNumbers(modulus, exponent)
  ) {
    return null;
  }

  return { key: value, kid };
}

interface IdentityVerifierConfigSnapshot {
  expectedAudience: string;
  issuer: string;
  now: number | undefined;
  clockToleranceSeconds: number;
  keysByKid: ReadonlyMap<string, CryptoKey>;
}

declare const identityVerifierConfigBrand: unique symbol;

/**
 * Immutable verifier configuration produced only by
 * {@link loadIdentityVerifierConfig}.
 */
export interface IdentityVerifierConfig {
  readonly expectedAudience: string;
  readonly issuer: string;
  readonly clockToleranceSeconds: number;
  readonly keyIds: readonly string[];
  readonly [identityVerifierConfigBrand]: true;
}

const identityVerifierConfigSnapshots = new WeakMap<
  IdentityVerifierConfig,
  IdentityVerifierConfigSnapshot
>();

/** Why identity verification CONFIG failed to load. Operator error, not a token error. */
export type IdentityVerifierConfigErrorReason =
  | "jwks_missing"
  | "jwks_malformed"
  | "issuer_missing"
  | "issuer_unsupported"
  | "audience_missing"
  | "audience_malformed"
  | "timing_invalid";

export interface LoadIdentityVerifierConfigInput {
  /** Raw JWKS JSON string, e.g. the `CAIL_IDENTITY_JWKS` environment value. */
  jwks: string | undefined;
  /** Exact expected issuer, e.g. the `CAIL_IDENTITY_ISSUER` environment value. */
  issuer: string | undefined;
  /** Required scalar `aud` value for this service. */
  expectedAudience: string | undefined;
  /**
   * Optional exact-match authority for acceptable configured issuers.
   * Defaults to CAIL's one canonical standalone Doorway issuer.
   */
  supportedIssuers?: readonly string[];
  /** Test-only fixed Unix time. Production callers should omit this. */
  now?: number;
  /** Symmetric clock leeway in seconds. Default 60; maximum 300. */
  clockToleranceSeconds?: number;
}

export type LoadIdentityVerifierConfigResult =
  | { ok: true; config: IdentityVerifierConfig }
  | { ok: false; reason: IdentityVerifierConfigErrorReason };

interface RawVerifierConfigOptions {
  jwks: unknown;
  issuer: unknown;
  expectedAudience: unknown;
  supportedIssuers: unknown;
  now: unknown;
  clockToleranceSeconds: unknown;
}

function snapshotVerifierConfigOptions<Value>(
  input: Value,
): RawVerifierConfigOptions | null {
  try {
    if (!isPlainObject(input)) return null;
    return {
      jwks: ownProp(input, "jwks"),
      issuer: ownProp(input, "issuer"),
      expectedAudience: ownProp(input, "expectedAudience"),
      supportedIssuers: ownProp(input, "supportedIssuers"),
      now: ownProp(input, "now"),
      clockToleranceSeconds: snapshotOwnProperty(
        input,
        "clockToleranceSeconds",
      ),
    };
  } catch {
    return null;
  }
}

function isCanonicalIssuer(value: string): boolean {
  if (
    value === "" ||
    ASCII_WHITESPACE_CHARACTER.test(value) ||
    containsControlCharacter(value)
  ) {
    return false;
  }
  try {
    const parsed = new URL(value);
    return (
      parsed.protocol === "https:" &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.search === "" &&
      parsed.hash === "" &&
      parsed.href === value
    );
  } catch {
    return false;
  }
}

function isValidAudience<Value>(value: Value): value is Value & string {
  const text = stringFrom(value);
  return (
    text !== undefined &&
    text !== "" &&
    text.trim() !== "" &&
    !containsControlCharacter(text)
  );
}

function isWithinJwksJsonDepth<Value>(value: Value): boolean {
  const pending: Array<{ value: unknown; depth: number }> = [
    { value, depth: 0 },
  ];
  while (pending.length > 0) {
    const current = pending.pop()!;
    if (current.depth > MAX_JWKS_JSON_DEPTH) return false;
    const childDepth = current.depth + 1;
    const array = unknownArrayFrom(current.value);
    if (array !== undefined) {
      for (let index = array.length - 1; index >= 0; index -= 1) {
        pending.push({ value: array[index], depth: childDepth });
      }
      continue;
    }

    const record = plainRecordFrom(current.value);
    if (record === undefined) continue;
    const keys = Object.keys(record.owner);
    for (let index = keys.length - 1; index >= 0; index -= 1) {
      const key = keys[index]!;
      pending.push({ value: record.read(key), depth: childDepth });
    }
  }
  return true;
}

/**
 * Load, validate, import, and snapshot the complete verifier configuration.
 *
 * Every caller-supplied option is read at most once. JWKS data must arrive as
 * JSON, so imported keys have own-data properties rather than live
 * accessors/proxies. A failed load is an owned service-configuration error;
 * callers map it to service unavailable. Only a successfully loaded snapshot
 * may be passed to {@link verifyIdentityJwt}.
 */
export async function loadIdentityVerifierConfig(
  input: LoadIdentityVerifierConfigInput,
): Promise<LoadIdentityVerifierConfigResult> {
  const raw = snapshotVerifierConfigOptions(input);
  if (raw === null) return { ok: false, reason: "jwks_missing" };

  const jwksText = stringFrom(raw.jwks);
  if (jwksText === undefined || jwksText.replace(ASCII_WHITESPACE, "") === "") {
    return { ok: false, reason: "jwks_missing" };
  }

  const parsedJwks = parseJsonRecord(jwksText);
  if (parsedJwks === null) return { ok: false, reason: "jwks_malformed" };
  if (!isWithinJwksJsonDepth(parsedJwks)) {
    return { ok: false, reason: "jwks_malformed" };
  }
  const keys = ownProp(parsedJwks, "keys");
  const keyArray = unknownArrayFrom(keys);
  if (keyArray === undefined || keyArray.length === 0) {
    return { ok: false, reason: "jwks_malformed" };
  }

  const keyRecords: EligibleRsaVerificationJwk[] = [];
  const keyIds = new Set<string>();
  for (const key of keyArray) {
    if (!isPlainObject(key)) {
      return { ok: false, reason: "jwks_malformed" };
    }
    const eligibleKey = snapshotRsaVerificationJwk(key);
    if (eligibleKey === null || keyIds.has(eligibleKey.kid)) {
      return { ok: false, reason: "jwks_malformed" };
    }
    keyIds.add(eligibleKey.kid);
    keyRecords.push(eligibleKey);
  }

  const issuer = stringFrom(raw.issuer);
  if (issuer === undefined || issuer === "") {
    return { ok: false, reason: "issuer_missing" };
  }
  if (!isCanonicalIssuer(issuer)) {
    return { ok: false, reason: "issuer_unsupported" };
  }

  let supportedIssuers: string[];
  if (raw.supportedIssuers === undefined) {
    supportedIssuers = [CAIL_CANONICAL_ISSUER];
  } else {
    const snapshot = snapshotStringArray(raw.supportedIssuers);
    if (
      snapshot === null ||
      new Set(snapshot).size !== snapshot.length ||
      !snapshot.every(isCanonicalIssuer)
    ) {
      return { ok: false, reason: "issuer_unsupported" };
    }
    supportedIssuers = snapshot;
  }
  if (!supportedIssuers.includes(issuer)) {
    return { ok: false, reason: "issuer_unsupported" };
  }

  if (raw.expectedAudience === undefined || raw.expectedAudience === "") {
    return { ok: false, reason: "audience_missing" };
  }
  const expectedAudience = stringFrom(raw.expectedAudience);
  if (expectedAudience === undefined || expectedAudience === "") {
    return { ok: false, reason: "audience_malformed" };
  }
  if (!isValidAudience(expectedAudience)) {
    return { ok: false, reason: "audience_malformed" };
  }

  let now: number | undefined;
  if (raw.now !== undefined) {
    now = numberFrom(raw.now);
    if (now === undefined || !Number.isFinite(now) || Math.abs(now) > MAX_DATE_SECONDS) {
      return { ok: false, reason: "timing_invalid" };
    }
  }
  const clockToleranceSeconds =
    raw.clockToleranceSeconds === undefined
      ? 60
      : numberFrom(raw.clockToleranceSeconds);
  if (
    clockToleranceSeconds === undefined ||
    clockToleranceSeconds < 0 ||
    clockToleranceSeconds > MAX_CLOCK_TOLERANCE_SECONDS
  ) {
    return { ok: false, reason: "timing_invalid" };
  }

  // JSON.parse returns local own-data values. Only validated key snapshots are
  // read below, and the parsed JWKS is never exposed through the config, so
  // recursively freezing ignored metadata would add work without protecting
  // the immutable verifier snapshot.
  const keysByKid = new Map<string, CryptoKey>();
  try {
    for (const { key, kid } of keyRecords) {
      const imported = await importJWK(key, "RS256");
      if (imported instanceof Uint8Array || imported.type !== "public") {
        return { ok: false, reason: "jwks_malformed" };
      }
      keysByKid.set(kid, imported);
    }
  } catch {
    return { ok: false, reason: "jwks_malformed" };
  }

  // SAFETY: every field was validated above, and the frozen object is branded
  // before it is entered into the private snapshot map.
  const config = Object.freeze({
    expectedAudience,
    issuer,
    clockToleranceSeconds,
    keyIds: Object.freeze([...keyIds]),
  }) as IdentityVerifierConfig;
  identityVerifierConfigSnapshots.set(config, {
    expectedAudience,
    issuer,
    now,
    clockToleranceSeconds,
    keysByKid,
  });
  return { ok: true, config };
}

async function verifyIdentityJwtInternal<Value>(
  token: Value,
  config: IdentityVerifierConfigSnapshot,
): Promise<CailIdentity | null> {
  const tokenText = stringFrom(token);
  if (tokenText === undefined) return null;

  const inspected = inspectCailJwt(tokenText);
  if (!inspected) return null;

  const kid = stringFrom(ownProp(inspected.header, "kid"));
  if (kid === undefined) return null;
  const key = config.keysByKid.get(kid);
  if (key === undefined) return null;

  const exp = ownProp(inspected.payload, "exp");
  const aud = ownProp(inspected.payload, "aud");
  const iss = ownProp(inspected.payload, "iss");
  const nbf = ownProp(inspected.payload, "nbf");
  const sub = ownProp(inspected.payload, "sub");
  if (!isFiniteNumber(exp)) return null;
  if (!hasExactAudience(aud, config.expectedAudience)) return null;
  const issuer = stringFrom(iss);
  if (issuer === undefined || issuer === "" || issuer !== config.issuer) {
    return null;
  }
  if (nbf !== undefined && !isFiniteNumber(nbf)) return null;
  if (!isCailSubject(sub)) return null;

  try {
    await jwtVerify(tokenText, key, {
      algorithms: ["RS256"],
      audience: config.expectedAudience,
      issuer: config.issuer,
      requiredClaims: ["exp", "sub"],
      clockTolerance: config.clockToleranceSeconds,
      currentDate:
        config.now === undefined ? new Date() : new Date(config.now * 1000),
    });
  } catch {
    return null;
  }

  const email = ownProp(inspected.payload, "email");
  const name = ownProp(inspected.payload, "name");
  const entitlements = ownProp(inspected.payload, "entitlements");
  const operationalSubject = ownProp(inspected.payload, "log_sub");
  if (
    operationalSubject !== undefined &&
    !isCailOperationalSubject(operationalSubject)
  ) {
    return null;
  }
  const identity: CailIdentity = {
    subject: sub,
    email: stringFrom(email),
    name: stringFrom(name),
    entitlements: [],
  };
  if (operationalSubject !== undefined) identity.operationalSubject = operationalSubject;
  const entitlementValues = unknownArrayFrom(entitlements);
  if (entitlementValues !== undefined) {
    identity.entitlements = entitlementValues.flatMap((item) => {
      const text = stringFrom(item);
      return text === undefined ? [] : [text];
    });
  }
  return identity;
}

/**
 * Verify a CAIL RS256 identity JWT using an immutable validated snapshot.
 *
 * Invalid tokens return `null`. Passing anything other than a snapshot from
 * {@link loadIdentityVerifierConfig} is a programmer/configuration error and
 * throws, so it cannot be mislabeled as invalid credentials.
 */
export async function verifyIdentityJwt(
  token: string,
  config: IdentityVerifierConfig,
): Promise<CailIdentity | null> {
  const snapshot = identityVerifierConfigSnapshots.get(config);
  if (snapshot === undefined) {
    throw new TypeError(
      "config must be a snapshot returned by loadIdentityVerifierConfig.",
    );
  }
  try {
    return await verifyIdentityJwtInternal(token, snapshot);
  } catch {
    return null;
  }
}

/* ── Identity keyring transport ─────────────────────────────────────────── */

/**
 * Header carrying the identity JWT addressed to the receiving application's
 * own audience. Canonical name for what every consumer already reads.
 */
const CAIL_IDENTITY_JWT_HEADER = "x-cail-identity-jwt";

/**
 * Header carrying the same person's gateway-audience identity JWT
 * (`aud: "cail:gateway"`), for the application to forward verbatim to CAIL
 * Model API when acting for the person. Optional: only routes whose tools
 * call the gateway receive it.
 */
const CAIL_GATEWAY_IDENTITY_JWT_HEADER = "x-cail-gateway-identity-jwt";

/** The audience every gateway keyring leg must carry. */
export const CAIL_GATEWAY_AUDIENCE = "cail:gateway";

/**
 * A signed-in person's audience-bound tokens as delivered by the issuing
 * doorway. Transport shape only — nothing here is verified. The application
 * MUST verify `appJwt` against its own audience before trusting anything,
 * and MUST pass `gatewayJwt` through {@link verifyKeyringGatewayJwt} before
 * storing or forwarding it. Claims inside `gatewayJwt` are never authority
 * for the application.
 */
interface IdentityKeyring {
  appJwt: string;
  gatewayJwt?: string;
}

const KEYRING_JWT_MAX_LENGTH = 8_192;
const COMPACT_JWS_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

function isCompactJwsToken<Value>(value: Value): value is Value & string {
  const text = stringFrom(value);
  return (
    text !== undefined &&
    text.length > 0 &&
    text.length <= KEYRING_JWT_MAX_LENGTH &&
    COMPACT_JWS_PATTERN.test(text)
  );
}

/**
 * Read a keyring from request headers. Structural transport parsing only —
 * no signature, audience, expiry, or subject checks happen here.
 *
 * Fail-closed rule: a header that is present but not a single well-shaped
 * compact JWS invalidates the whole keyring (`null`), rather than salvaging
 * the other leg. Duplicate headers join with a comma and therefore fail the
 * shape check by construction. An absent identity header yields `null`; an
 * absent gateway header yields a keyring without that leg.
 */
export function readIdentityKeyring(headers: Headers): IdentityKeyring | null {
  const appJwt = headers.get(CAIL_IDENTITY_JWT_HEADER);
  if (appJwt === null) return null;
  if (!isCompactJwsToken(appJwt)) return null;
  const gatewayJwt = headers.get(CAIL_GATEWAY_IDENTITY_JWT_HEADER);
  if (gatewayJwt === null) return { appJwt };
  if (!isCompactJwsToken(gatewayJwt)) return null;
  return { appJwt, gatewayJwt };
}

/**
 * Verify a keyring's gateway leg before the application stores or forwards
 * it: full {@link verifyIdentityJwt} verification against a gateway-audience
 * config, plus the keyring invariant that its subject equals the already
 * verified app-leg subject. Returns the gateway leg's identity, or `null`
 * when the leg is absent, invalid, or belongs to a different person.
 *
 * `config` must come from {@link loadIdentityVerifierConfig} with
 * `expectedAudience: "cail:gateway"`; anything else is a programmer error
 * and throws, so a misconfigured verifier cannot pass as invalid tokens.
 */
export async function verifyKeyringGatewayJwt(
  keyring: IdentityKeyring,
  config: IdentityVerifierConfig,
  expectedSubject: string,
): Promise<CailIdentity | null> {
  if (config.expectedAudience !== CAIL_GATEWAY_AUDIENCE) {
    throw new TypeError(
      `config.expectedAudience must be "${CAIL_GATEWAY_AUDIENCE}".`,
    );
  }
  if (!isCailSubject(expectedSubject)) {
    throw new TypeError("expectedSubject must be a canonical CAIL subject.");
  }
  if (keyring.gatewayJwt === undefined) return null;
  const identity = await verifyIdentityJwt(keyring.gatewayJwt, config);
  if (identity === null) return null;
  return identity.subject === expectedSubject ? identity : null;
}
