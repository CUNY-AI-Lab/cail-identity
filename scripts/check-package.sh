#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p .release
bun pm pack --ignore-scripts --filename .release/package.tgz
package_path="$PWD/.release/package.tgz"
package_root="$PWD"
consumer_dir="$(mktemp -d)"
trap 'rm -rf "$consumer_dir"' EXIT
cp scripts/package-consumer.mjs "$consumer_dir/consumer.mjs"
cd "$consumer_dir"
bun add --ignore-scripts "$package_path"
node consumer.mjs
cp consumer.mjs consumer.mts
"$package_root/node_modules/.bin/tsc" --noEmit --strict --target ES2022 \
  --module NodeNext --types node --typeRoots "$package_root/node_modules/@types" consumer.mts
