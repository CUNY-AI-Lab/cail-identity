-- Lua reference for contract/subject-derivation-v2.json.
--
-- This is not wired into a live gateway. Consumers should copy the framing
-- behavior into their trusted identity producer and run the shared vectors
-- before changing any ownership IDs.

local M = {}

local ASCII_EDGE_WHITESPACE = "^%s*(.-)%s*$"
local CUNY_LOGIN_REALM = "@LOGIN%.CUNY%.EDU$"

M.OWNERSHIP_DOMAIN = "cail-identity/ownership-subject:v2"
M.OPERATIONAL_DOMAIN = "cail-identity/operational-subject:v2"

function M.canonicalize_sub(subject)
  assert(type(subject) == "string", "CUNY OIDC subject must be a string")
  local canonical = subject:match(ASCII_EDGE_WHITESPACE):upper()
  canonical = canonical:gsub(CUNY_LOGIN_REALM, "")
  assert(canonical ~= "", "CUNY OIDC subject must not be empty")
  assert(not canonical:find("[%z\1-\31\127]"),
    "CUNY OIDC subject must not contain control characters")
  return canonical
end

local function frame(domain, issuer, canonical_subject)
  assert(type(issuer) == "string" and issuer ~= "",
    "issuer must be a non-empty string")
  assert(not issuer:find("[%z\1-\31\127]"),
    "issuer must not contain control characters")
  return domain .. ":" .. #issuer .. ":" .. issuer
    .. #canonical_subject .. ":" .. canonical_subject
end

function M.ownership_material(issuer, oidc_subject)
  return frame(M.OWNERSHIP_DOMAIN, issuer, M.canonicalize_sub(oidc_subject))
end

function M.operational_material(issuer, oidc_subject)
  return frame(M.OPERATIONAL_DOMAIN, issuer, M.canonicalize_sub(oidc_subject))
end

local function validate_salt(salt)
  assert(type(salt) == "string" and #salt >= 32,
    "subject salt must contain at least 32 UTF-8 bytes")
  assert(not salt:find("[%z\1-\31\127]"),
    "subject salt must not contain control characters")
end

local function derive(prefix, hmac_sha256_hex, salt, material)
  assert(type(hmac_sha256_hex) == "function",
    "hmac_sha256_hex must be a function")
  validate_salt(salt)
  local digest = hmac_sha256_hex(salt, material)
  assert(type(digest) == "string" and digest:match("^[0-9a-f]+$")
      and #digest == 64,
    "hmac_sha256_hex must return 64 lowercase hexadecimal characters")
  return prefix .. digest:sub(1, 32)
end

function M.derive_ownership(hmac_sha256_hex, salt, issuer, oidc_subject)
  return derive("cail-", hmac_sha256_hex, salt,
    M.ownership_material(issuer, oidc_subject))
end

function M.derive_operational(hmac_sha256_hex, salt, issuer, oidc_subject)
  return derive("cail-v1-", hmac_sha256_hex, salt,
    M.operational_material(issuer, oidc_subject))
end

return M
