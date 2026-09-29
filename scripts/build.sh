#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

cargo build --release --locked
npm --prefix web ci
npm --prefix web run build

echo "release binary: target/release/tokenstream"
echo "administration page: web/dist"
