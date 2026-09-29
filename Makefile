# Developer shortcuts. Run `make` or `make help` to list targets.

.PHONY: help lint fmt fmt-check clippy \
  web-deps web-check web-test web-build \
  test test-unit test-web test-compat \
  build package gate ci run clean

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Lint"
	@echo "  lint         rustfmt --check, Clippy (-D warnings), and web typecheck"
	@echo "  fmt          Apply rustfmt"
	@echo "  fmt-check    rustfmt --check"
	@echo "  clippy       Clippy with warnings denied"
	@echo "  web-check    Administration page typecheck"
	@echo ""
	@echo "Test"
	@echo "  test         Locked cargo test suite"
	@echo "  test-unit    Library unit tests only"
	@echo "  test-web     Administration page unit tests"
	@echo "  test-compat  Pinned client compatibility suite"
	@echo ""
	@echo "Build"
	@echo "  build        Release binary with the administration page"
	@echo "  package      Alias for build"
	@echo "  web-build    Administration page production build"
	@echo ""
	@echo "Other"
	@echo "  ci           Local CI checks (frontend + lint + tests)"
	@echo "  gate         Full release verification"
	@echo "  run          Run the gateway with cargo"
	@echo "  web-deps     Install administration frontend dependencies"
	@echo "  clean        Remove Rust and frontend build artifacts"

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

clippy:
	cargo clippy --locked --all-targets -- -D warnings

web-deps:
	npm --prefix web ci

web-check:
	npm --prefix web run check

web-test:
	npm --prefix web run test

web-build:
	npm --prefix web run build

lint: fmt-check clippy web-check

test:
	cargo test --locked

test-unit:
	cargo test --locked --lib

test-web:
	npm --prefix web run test

test-compat:
	npm --prefix compatibility ci --ignore-scripts
	npm --prefix compatibility test

build:
	./scripts/build.sh

package: build

ci:
	npm --prefix web ci
	npm --prefix web run check
	npm --prefix web run test
	npm --prefix web run build
	cargo fmt --check
	cargo clippy --locked --all-targets -- -D warnings
	cargo test --locked

gate:
	./scripts/release-gate.sh

run:
	cargo run --locked

clean:
	cargo clean
	rm -rf web/dist dist staging
