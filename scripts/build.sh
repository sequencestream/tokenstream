#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

npm --prefix web ci
npm --prefix web run build
TOKENSTREAM_SKIP_FRONTEND_BUILD=1 cargo build --release --locked

echo "release binary: target/release/tokenstream"
