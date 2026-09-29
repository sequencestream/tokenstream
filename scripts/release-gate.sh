#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary_postgres=""
postgres_container=""
postgres_ctl=""

cleanup() {
  if [ -n "$temporary_postgres" ]; then
    if [ -n "$postgres_ctl" ] && [ -f "$temporary_postgres/data/postmaster.pid" ]; then
      "$postgres_ctl" -D "$temporary_postgres/data" -m fast stop >/dev/null
    fi
    rm -rf "$temporary_postgres"
  fi
  if [ -n "$postgres_container" ]; then
    if docker inspect "$postgres_container" >/dev/null 2>&1; then
      docker stop "$postgres_container" >/dev/null
    fi
  fi
}
trap cleanup EXIT HUP INT TERM

stage() {
  echo
  echo "==> $1"
}

cd "$repository_root"

stage "administration frontend"
npm --prefix web ci
npm --prefix web run check
npm --prefix web run test
npm --prefix web run build
export TOKENSTREAM_SKIP_FRONTEND_BUILD=1

stage "format and static analysis"
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings

if [ -z "${TOKENSTREAM_TEST_POSTGRES_URL:-}" ]; then
  stage "ephemeral PostgreSQL"
  initdb_path=$(command -v initdb 2>/dev/null || true)
  postgres_bin=""
  if [ -n "$initdb_path" ] && [ -x "$(dirname "$initdb_path")/postgres" ]; then
    postgres_bin=$(dirname "$initdb_path")
  elif command -v brew >/dev/null 2>&1; then
    brew_postgres=$(brew --prefix postgresql@18 2>/dev/null || true)
    if [ -n "$brew_postgres" ] && [ -x "$brew_postgres/bin/postgres" ]; then
      postgres_bin="$brew_postgres/bin"
    fi
  fi
  if [ -n "$postgres_bin" ] && [ -x "$postgres_bin/initdb" ] && [ -x "$postgres_bin/pg_ctl" ]; then
    temporary_postgres=$(mktemp -d "${TMPDIR:-/tmp}/tokenstream-postgres.XXXXXX")
    "$postgres_bin/initdb" -D "$temporary_postgres/data" --auth=trust --no-locale >/dev/null
    postgres_port=${TOKENSTREAM_TEST_POSTGRES_PORT:-55432}
    postgres_ctl="$postgres_bin/pg_ctl"
    "$postgres_ctl" -D "$temporary_postgres/data" \
      -l "$temporary_postgres/postgres.log" \
      -o "-F -h 127.0.0.1 -p $postgres_port" start >/dev/null
  elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    postgres_container="tokenstream-release-postgres-$$"
    postgres_image=${TOKENSTREAM_TEST_POSTGRES_IMAGE:-postgres:18}
    docker run -d --rm --name "$postgres_container" \
      -e POSTGRES_HOST_AUTH_METHOD=trust \
      -p 127.0.0.1::5432 "$postgres_image" >/dev/null
    postgres_binding=$(docker port "$postgres_container" 5432/tcp)
    postgres_port=${postgres_binding##*:}
    attempts=0
    until docker exec "$postgres_container" pg_isready -U postgres >/dev/null 2>&1; do
      attempts=$((attempts + 1))
      if [ "$attempts" -ge 30 ]; then
        echo "ephemeral PostgreSQL did not become ready" >&2
        exit 1
      fi
      sleep 1
    done
  else
    echo "TOKENSTREAM_TEST_POSTGRES_URL is required when no PostgreSQL server or Docker daemon is available" >&2
    exit 1
  fi
  TOKENSTREAM_TEST_POSTGRES_URL="postgres://127.0.0.1:$postgres_port/postgres"
  export TOKENSTREAM_TEST_POSTGRES_URL
fi

# A supplied server must be reachable. An unreachable one is a gate failure,
# not a reason for the dual-backend layers to be recorded as unexecuted.
postgres_ready=false
for isready in "${postgres_bin:-}/pg_isready" "$(command -v pg_isready 2>/dev/null || true)"; do
  if [ -x "$isready" ] && "$isready" -q -d "$TOKENSTREAM_TEST_POSTGRES_URL" 2>/dev/null; then
    postgres_ready=true
    break
  fi
done
if [ "$postgres_ready" != true ]; then
  echo "TOKENSTREAM_TEST_POSTGRES_URL is set but no PostgreSQL server is reachable at it" >&2
  exit 1
fi

stage "unit, repository, protocol, and security suites"
cargo test --locked

stage "mixed HTTP/SSE and WebSocket component load profile"
cargo test --locked --test release_load_profile \
  mixed_long_lived_transports_reach_stable_bounded_memory \
  -- --ignored --exact --nocapture

stage "sustained mixed load against the real gateway process"
cargo test --locked --test gateway_load -- --nocapture

stage "pinned client compatibility"
npm --prefix compatibility ci --ignore-scripts
npm --prefix compatibility test

stage "pinned clients through the production gateway"
npm --prefix compatibility run test:gateway

stage "release gate passed"
