#!/usr/bin/env bash

set -euo pipefail

readonly LUAJIT_COMMIT="63c8f1a9b479ba5518cf6a170ff7729178bc3cfd"
readonly LUAJIT_ARCHIVE_SHA256="8cad76f444b76001b7123dc626c5d0bfc24f1f790333737443345f7e6b41bb5f"
readonly LUAJIT_ARCHIVE_URL="https://codeload.github.com/LuaJIT/LuaJIT/tar.gz/${LUAJIT_COMMIT}"

die() {
  printf 'install-luajit: %s\n' "$1" >&2
  exit 1
}

command -v curl >/dev/null 2>&1 || die 'curl is required'
command -v tar >/dev/null 2>&1 || die 'tar is required'
command -v make >/dev/null 2>&1 || die 'make is required'
command -v awk >/dev/null 2>&1 || die 'awk is required'

if [[ -z "${GITHUB_PATH:-}" ]]; then
  die 'GITHUB_PATH must be set by the GitHub Actions runner'
fi

if ! make --version 2>/dev/null | grep -q 'GNU Make'; then
  die 'GNU Make is required by the LuaJIT build system'
fi

runtime_dir="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
[[ -d "$runtime_dir" ]] || die "temporary directory does not exist: $runtime_dir"

build_dir="$(mktemp -d "$runtime_dir/luajit-build.XXXXXX")"
install_dir="$(mktemp -d "$runtime_dir/luajit-install.XXXXXX")"
trap 'rm -rf "$build_dir"' EXIT

archive="$build_dir/luajit.tar.gz"
curl --fail --silent --show-error --location --retry 3 --retry-all-errors \
  "$LUAJIT_ARCHIVE_URL" \
  --output "$archive"

if command -v sha256sum >/dev/null 2>&1; then
  archive_sha256="$(sha256sum "$archive" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  archive_sha256="$(shasum -a 256 "$archive" | awk '{print $1}')"
else
  die 'sha256sum or shasum is required to verify the LuaJIT archive'
fi

[[ "$archive_sha256" == "$LUAJIT_ARCHIVE_SHA256" ]] || \
  die "LuaJIT archive checksum mismatch: $archive_sha256"

tar --extract --gzip --file "$archive" --directory "$build_dir"
source_dir="$build_dir/LuaJIT-$LUAJIT_COMMIT"
[[ -d "$source_dir" ]] || die "expected LuaJIT source directory is missing: $source_dir"

if [[ "$(uname -s)" == "Darwin" ]]; then
  export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-12.0}"
fi

make -C "$source_dir" PREFIX="$install_dir"
make -C "$source_dir" PREFIX="$install_dir" install

[[ -x "$install_dir/bin/luajit" ]] || die "LuaJIT was not installed under $install_dir"
"$install_dir/bin/luajit" -e 'assert(jit and jit.version); print(jit.version)'

printf '%s\n' "$install_dir/bin" >>"$GITHUB_PATH"
printf 'Installed LuaJIT from %s under %s\n' "$LUAJIT_COMMIT" "$install_dir"
