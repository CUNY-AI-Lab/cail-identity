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
 *   - Subject derivation is explicit and intended only for a trusted CUNY
 *     authentication boundary, never for user-controlled request data.
 */

import { base64url, importJWK, jwtVerify } from "jose";

export interface CailIdentity {
  subject: string;
  /** Separately keyed pseudonym for privacy-bounded operational events. */
  operationalSubject?: string;
  email?: string;
  name?: string;
  entitlements: string[];
}

/** Stable pseudonymous identifier shared across CAIL applications. */
export const CAIL_SUBJECT_PATTERN = /^cail-[0-9a-f]{32}$/;

/** True only for the canonical stable CAIL subject representation. */
export function isCailSubject(value: unknown): value is string {
  return typeof value === "string" && CAIL_SUBJECT_PATTERN.test(value);
}

const CUNY_LOGIN_REALM = "@LOGIN.CUNY.EDU";
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/;
// ASCII whitespace only — the exact set LuaJIT's `%s` pattern trims in the gate
// (space, tab, newline, vertical tab, form feed, carriage return).
const ASCII_WHITESPACE = /^[ \t\n\v\f\r]+|[ \t\n\v\f\r]+$/g;
const ASCII_WHITESPACE_CHARACTER = /[ \t\n\v\f\r]/;
const encoder = new TextEncoder();

function snapshotOwnProperty(
  value: Record<string, unknown>,
  key: string,
): unknown {
  return Object.hasOwn(value, key) ? value[key] : undefined;
}

function snapshotSubjectSalt(
  value: unknown,
  optionName: string,
): Uint8Array<ArrayBuffer> {
  const bytes = typeof value === "string" ? encoder.encode(value) : null;
  if (
    typeof value !== "string" ||
    CONTROL_CHARACTER.test(value) ||
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

function snapshotSubjectDerivationOptions(
  options: unknown,
  saltOptionName: "subjectSalt" | "operationalSubjectSalt",
): SubjectDerivationSnapshot {
  let issuer: unknown;
  let oidcSubject: unknown;
  let salt: unknown;
  try {
    if (typeof options !== "object" || options === null) {
      throw new TypeError("options must be an object.");
    }
    const record = options as Record<string, unknown>;
    issuer = snapshotOwnProperty(record, "issuer");
    oidcSubject = snapshotOwnProperty(record, "oidcSubject");
    salt = snapshotOwnProperty(record, saltOptionName);
  } catch {
    throw new TypeError("subject derivation options could not be read.");
  }

  if (
    typeof issuer !== "string" ||
    issuer === "" ||
    CONTROL_CHARACTER.test(issuer)
  ) {
    throw new TypeError("issuer must be a non-empty string without controls.");
  }

  const saltBytes = snapshotSubjectSalt(salt, saltOptionName);
  const canonicalSubject = canonicalizeCunySubject(
    oidcSubject as string,
  );
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
export function canonicalizeCunySubject(subject: string): string {
  if (typeof subject !== "string") {
    throw new TypeError("CUNY OIDC subject must be a string.");
  }
  // Trim edge ASCII whitespace first (a trailing newline is trimmed, as the
  // gate does), then fail closed on any interior control character.
  const trimmed = subject.replace(ASCII_WHITESPACE, "");
  if (CONTROL_CHARACTER.test(trimmed)) {
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
export const APP_SUBJECT_PATTERN = /^app-[0-9a-f]{32}$/;

/** True only for the canonical stable CAIL app-principal subject. */
export function isAppSubject(value: unknown): value is string {
  return typeof value === "string" && APP_SUBJECT_PATTERN.test(value);
}

/** A stable subject accepted by CAIL accounting and ownership boundaries. */
export type CailPrincipalSubject = string;

/**
 * True for a canonical user or application principal subject.
 *
 * This helper validates identifiers only. It does not authenticate a caller;
 * services still obtain user subjects from a verified identity JWT and app
 * subjects from their trusted control plane.
 */
export function isCailPrincipalSubject(
  value: unknown,
): value is CailPrincipalSubject {
  return isCailSubject(value) || isAppSubject(value);
}

export const CAIL_OPERATIONAL_SUBJECT_PATTERN = /^cail-v1-[0-9a-f]{32}$/;

export function isCailOperationalSubject(value: unknown): value is string {
  return (
    typeof value === "string" && CAIL_OPERATIONAL_SUBJECT_PATTERN.test(value)
  );
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
  if (
    typeof appId !== "string" ||
    appId === "" ||
    CONTROL_CHARACTER.test(appId) ||
    appId.replace(ASCII_WHITESPACE, "") !== appId
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
    await crypto.subtle.sign("HMAC", key, encoder.encode(`app|${appId}`)),
  );
  return `app-${bytesToHex(digest).slice(0, 32)}`;
}

/** Canonical production issuer — include it in `supportedIssuers` to accept prod. */
export const CAIL_CANONICAL_ISSUER = "https://tools.ailab.gc.cuny.edu/cail-sso";
/** Staging issuer — include it in `supportedIssuers` to accept staging. */
export const CAIL_STAGING_ISSUER = "https://tools.cuny.qzz.io/cail-sso";

// fatal:true — RFC 7519 §7.2 / RFC 8725 §3.7 require the header and payload
// to be valid UTF-8 JSON. The default lenient decoder would smuggle invalid
// bytes through as U+FFFD instead of rejecting; fatal mode throws inside the
// existing try/catch, so malformed bytes fail closed to null.
const decoder = new TextDecoder("utf-8", { fatal: true });

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function ownProp(obj: Record<string, unknown>, key: string): unknown {
  return Object.hasOwn(obj, key) ? obj[key] : undefined;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

interface InspectedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
}

const MAX_CLOCK_TOLERANCE_SECONDS = 300;
const MAX_DATE_SECONDS = 8_640_000_000_000;
const MIN_RSA_MODULUS_BITS = 2048;

function isCanonicalBase64url(value: unknown): value is string {
  if (typeof value !== "string" || value === "") return false;
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return false;
  try {
    return base64url.encode(base64url.decode(value)) === value;
  } catch {
    return false;
  }
}

function decodeCanonicalBase64urlUInt(value: unknown): Uint8Array | null {
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

function inspectCailJwt(token: string): InspectedJwt | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const decoded: Uint8Array[] = [];
  try {
    for (const segment of parts) {
      if (!isCanonicalBase64url(segment)) return null;
      decoded.push(base64url.decode(segment));
    }

    const header: unknown = JSON.parse(decoder.decode(decoded[0]!));
    const payload: unknown = JSON.parse(decoder.decode(decoded[1]!));
    if (!isPlainObject(header) || !isPlainObject(payload)) return null;
    if (ownProp(header, "alg") !== "RS256") return null;
    const kid = ownProp(header, "kid");
    if (typeof kid !== "string" || kid === "") return null;
    if (Object.hasOwn(header, "crit")) return null;
    const b64 = ownProp(header, "b64");
    if (b64 !== undefined && b64 !== true) return null;

    return { header, payload };
  } catch {
    return null;
  }
}

function snapshotStringArray(value: unknown): string[] | null {
  try {
    if (!Array.isArray(value)) return null;
    const length: unknown = value.length;
    if (!Number.isSafeInteger(length) || (length as number) < 1) return null;
    const snapshot: string[] = [];
    for (let index = 0; index < (length as number); index += 1) {
      if (!Object.hasOwn(value, index)) return null;
      const item: unknown = value[index];
      if (typeof item !== "string" || item === "") return null;
      snapshot.push(item);
    }
    return snapshot;
  } catch {
    return null;
  }
}

function hasExactAudience(value: unknown, expected: string): boolean {
  return typeof value === "string" && value !== "" && value === expected;
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

function containsPrivateJwkMaterial(value: Record<string, unknown>): boolean {
  return PRIVATE_JWK_PARAMETERS.some((name) => Object.hasOwn(value, name));
}

interface EligibleRsaVerificationJwk {
  key: Record<string, unknown>;
  kid: string;
}

function snapshotRsaVerificationJwk(
  value: Record<string, unknown>,
): EligibleRsaVerificationJwk | null {
  const kid = ownProp(value, "kid");
  if (
    ownProp(value, "kty") !== "RSA" ||
    typeof kid !== "string" ||
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
   * Defaults to CAIL's canonical production and staging issuers.
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

function snapshotVerifierConfigOptions(
  input: unknown,
): RawVerifierConfigOptions | null {
  try {
    if (!isPlainObject(input)) return null;
    return {
      jwks: snapshotOwnProperty(input, "jwks"),
      issuer: snapshotOwnProperty(input, "issuer"),
      expectedAudience: snapshotOwnProperty(input, "expectedAudience"),
      supportedIssuers: snapshotOwnProperty(input, "supportedIssuers"),
      now: snapshotOwnProperty(input, "now"),
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
    CONTROL_CHARACTER.test(value)
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

function isValidAudience(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value !== "" &&
    value.trim() !== "" &&
    !CONTROL_CHARACTER.test(value)
  );
}

function freezeJsonValue(value: unknown): void {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) {
    return;
  }
  for (const child of Object.values(value)) freezeJsonValue(child);
  Object.freeze(value);
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

  if (
    typeof raw.jwks !== "string" ||
    raw.jwks.replace(ASCII_WHITESPACE, "") === ""
  ) {
    return { ok: false, reason: "jwks_missing" };
  }

  let parsedJwks: unknown;
  try {
    parsedJwks = JSON.parse(raw.jwks);
  } catch {
    return { ok: false, reason: "jwks_malformed" };
  }
  if (!isPlainObject(parsedJwks)) {
    return { ok: false, reason: "jwks_malformed" };
  }
  const keys = ownProp(parsedJwks, "keys");
  if (!Array.isArray(keys) || keys.length === 0) {
    return { ok: false, reason: "jwks_malformed" };
  }

  const keyRecords: EligibleRsaVerificationJwk[] = [];
  const keyIds = new Set<string>();
  for (const key of keys) {
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

  if (typeof raw.issuer !== "string" || raw.issuer === "") {
    return { ok: false, reason: "issuer_missing" };
  }
  if (!isCanonicalIssuer(raw.issuer)) {
    return { ok: false, reason: "issuer_unsupported" };
  }

  let supportedIssuers: string[];
  if (raw.supportedIssuers === undefined) {
    supportedIssuers = [CAIL_CANONICAL_ISSUER, CAIL_STAGING_ISSUER];
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
  if (!supportedIssuers.includes(raw.issuer)) {
    return { ok: false, reason: "issuer_unsupported" };
  }

  if (raw.expectedAudience === undefined || raw.expectedAudience === "") {
    return { ok: false, reason: "audience_missing" };
  }
  if (!isValidAudience(raw.expectedAudience)) {
    return { ok: false, reason: "audience_malformed" };
  }

  const now = raw.now;
  if (
    now !== undefined &&
    (!isFiniteNumber(now) || Math.abs(now) > MAX_DATE_SECONDS)
  ) {
    return { ok: false, reason: "timing_invalid" };
  }
  const clockToleranceSeconds =
    raw.clockToleranceSeconds === undefined ? 60 : raw.clockToleranceSeconds;
  if (
    !isFiniteNumber(clockToleranceSeconds) ||
    clockToleranceSeconds < 0 ||
    clockToleranceSeconds > MAX_CLOCK_TOLERANCE_SECONDS
  ) {
    return { ok: false, reason: "timing_invalid" };
  }

  try {
    freezeJsonValue(parsedJwks);
  } catch {
    return { ok: false, reason: "jwks_malformed" };
  }
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

  const config = Object.freeze({
    expectedAudience: raw.expectedAudience,
    issuer: raw.issuer,
    clockToleranceSeconds,
    keyIds: Object.freeze([...keyIds]),
  }) as unknown as IdentityVerifierConfig;
  identityVerifierConfigSnapshots.set(config, {
    expectedAudience: raw.expectedAudience,
    issuer: raw.issuer,
    now: now as number | undefined,
    clockToleranceSeconds,
    keysByKid,
  });
  return { ok: true, config };
}

async function verifyIdentityJwtInternal(
  token: string,
  config: IdentityVerifierConfigSnapshot,
): Promise<CailIdentity | null> {
  if (typeof token !== "string") return null;

  const inspected = inspectCailJwt(token);
  if (!inspected) return null;

  const kid = ownProp(inspected.header, "kid") as string;
  const key = config.keysByKid.get(kid);
  if (key === undefined) return null;

  const exp = ownProp(inspected.payload, "exp");
  const aud = ownProp(inspected.payload, "aud");
  const iss = ownProp(inspected.payload, "iss");
  const nbf = ownProp(inspected.payload, "nbf");
  const sub = ownProp(inspected.payload, "sub");
  if (!isFiniteNumber(exp)) return null;
  if (!hasExactAudience(aud, config.expectedAudience)) return null;
  if (
    typeof iss !== "string" ||
    iss === "" ||
    iss !== config.issuer
  ) {
    return null;
  }
  if (nbf !== undefined && !isFiniteNumber(nbf)) return null;
  if (!isCailSubject(sub)) return null;

  try {
    await jwtVerify(token, key, {
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
  return {
    subject: sub,
    ...(typeof operationalSubject === "string"
      ? { operationalSubject }
      : {}),
    email: typeof email === "string" ? email : undefined,
    name: typeof name === "string" ? name : undefined,
    entitlements: Array.isArray(entitlements)
      ? entitlements.filter((item): item is string => typeof item === "string")
      : [],
  };
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

/* ── Identity keyring transport (contract/identity-keyring-v1.json) ────── */

/**
 * Header carrying the identity JWT addressed to the receiving application's
 * own audience. Canonical name for what every consumer already reads.
 */
export const CAIL_IDENTITY_JWT_HEADER = "x-cail-identity-jwt";

/**
 * Header carrying the same person's gateway-audience identity JWT
 * (`aud: "cail:gateway"`), for the application to forward verbatim to CAIL
 * Model API when acting for the person. Optional: only routes whose tools
 * call the gateway receive it.
 */
export const CAIL_GATEWAY_IDENTITY_JWT_HEADER = "x-cail-gateway-identity-jwt";

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
export interface IdentityKeyring {
  appJwt: string;
  gatewayJwt?: string;
}

const KEYRING_JWT_MAX_LENGTH = 8_192;
const COMPACT_JWS_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

function isCompactJwsShape(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= KEYRING_JWT_MAX_LENGTH &&
    COMPACT_JWS_PATTERN.test(value)
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
  if (!isCompactJwsShape(appJwt)) return null;
  const gatewayJwt = headers.get(CAIL_GATEWAY_IDENTITY_JWT_HEADER);
  if (gatewayJwt === null) return { appJwt };
  if (!isCompactJwsShape(gatewayJwt)) return null;
  return { appJwt, gatewayJwt };
}

/**
 * Render a keyring as the headers the doorway (or a test harness) attaches.
 * Throws on structurally invalid tokens: a proxy must never emit a keyring
 * that its own reader would reject.
 */
export function identityKeyringHeaders(
  keyring: IdentityKeyring,
): Record<string, string> {
  if (!isCompactJwsShape(keyring.appJwt)) {
    throw new TypeError("appJwt is not a compact JWS.");
  }
  if (keyring.gatewayJwt === undefined) {
    return { [CAIL_IDENTITY_JWT_HEADER]: keyring.appJwt };
  }
  if (!isCompactJwsShape(keyring.gatewayJwt)) {
    throw new TypeError("gatewayJwt is not a compact JWS.");
  }
  return {
    [CAIL_IDENTITY_JWT_HEADER]: keyring.appJwt,
    [CAIL_GATEWAY_IDENTITY_JWT_HEADER]: keyring.gatewayJwt,
  };
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
