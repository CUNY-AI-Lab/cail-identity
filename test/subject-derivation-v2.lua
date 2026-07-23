local script_dir = arg[0]:match("^(.*)/[^/]+$") or "."
local derivation = dofile(script_dir .. "/../contract/subject-derivation-v2.lua")

if arg[1] then
  io.write(derivation.canonicalize_sub(arg[2]), "\n")
  io.write(derivation.ownership_material(arg[1], arg[2]), "\n")
  io.write(derivation.operational_material(arg[1], arg[2]), "\n")
  return
end

local bob = "http://identity:8090/cuny"
assert(derivation.canonicalize_sub("  Bob@login.cuny.edu  ") == "BOB")
assert(derivation.ownership_material(bob, "bob@login.cuny.edu")
  == "cail-identity/ownership-subject:v2:25:http://identity:8090/cuny3:BOB")
assert(derivation.operational_material(bob, "bob@login.cuny.edu")
  == "cail-identity/operational-subject:v2:25:http://identity:8090/cuny3:BOB")

local left = derivation.ownership_material("https://issuer.example/a", "b|c")
local right = derivation.ownership_material("https://issuer.example/a|B", "c")
assert(left ~= right, "v2 framing must separate the former delimiter collision")

local utf8 = derivation.ownership_material("https://issuer.example/ü", "straße")
assert(utf8
  == "cail-identity/ownership-subject:v2:25:https://issuer.example/ü7:STRAßE")

local seen_salt, seen_material
local function fake_hmac(salt, material)
  seen_salt, seen_material = salt, material
  return string.rep("a", 64)
end
local test_salt = "local-proof-subject-salt-do-not-use"
assert(derivation.derive_ownership(fake_hmac, test_salt, bob, "bob")
  == "cail-" .. string.rep("a", 32))
assert(seen_salt == test_salt)
assert(seen_material
  == "cail-identity/ownership-subject:v2:25:http://identity:8090/cuny3:BOB")

io.write("subject-derivation-v2 Lua vectors: OK\n")
