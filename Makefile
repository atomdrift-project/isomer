SHELL := /bin/sh
# isomer — supply-chain attack detection at a molecular level. The cargo bin,
# build artifact, and installed binary all share the name `isomer`.
BINARY = isomer

# Scrub GNU make's jobserver from cargo's environment, so build scripts that
# spawn their own `make` (e.g. tikv-jemalloc-sys, pulled in transitively via
# cleave) don't inherit a malformed MAKEFLAGS. Mirrors scan's Makefile.
CARGO = env -u MAKEFLAGS -u MAKELEVEL -u MFLAGS cargo

.PHONY: all build release install lint fix test demo validate-samples install-precommit clean help

# Trait set the sample audit judges with. Defaults to the working-tree
# traits-dev beside this repo when present, so the audit tracks trait edits;
# override CLEAVE_TRAITS_DIR to point elsewhere (or leave unset for bundled).
TRAITS_DIR ?= $(if $(wildcard ../traits-dev/.),../traits-dev,)

all: build

build:
	$(CARGO) build

release:
	$(CARGO) build --release

install: release
	$(CARGO) install --path .

# Three gates, cheapest first. `--check` (not `--all`) keeps rustfmt inside this
# package: `cargo fmt --all` also reformats local path dependencies, which would
# drag ../scan and ../cleave into isomer's lint run. `--all-targets` puts tests
# and examples under the same lints as the binary — clippy.toml relaxes only the
# panic lints there. `--locked` fails on a stale Cargo.lock instead of quietly
# rewriting it, so a lint run can't move a pinned git dep.
lint:
	$(CARGO) fmt --check
	$(CARGO) clippy --locked --all-targets -- -D warnings

# Auto-fix what clippy and rustfmt can fix on their own; fmt last so it tidies
# any code clippy rewrote. Same target set as `lint`.
fix:
	$(CARGO) clippy --fix --all-targets --allow-dirty --allow-staged
	$(CARGO) fmt

test:
	$(CARGO) test --quiet

# Run the curated real-world supply-chain pairs and narrate each verdict.
# Builds once, then hands the release binary to the demo script so the
# narration isn't interleaved with cargo output.
demo: release
	@sh scripts/demo.sh "./target/release/$(BINARY)"

# Self-audit against the supply-chain corpus: for every attack, before->during
# must be detected, and during->after / before->after must not. Prints a
# violations report and exits non-zero on any miss or false positive. Point at
# the corpus with ISOMER_SAMPLES_DIR (default ~/src/supplychain-attack-data);
# it skips cleanly (exit 2) when the corpus is absent.
validate-samples: release
	@CLEAVE_TRAITS_DIR="$(TRAITS_DIR)" \
		python3 scripts/validate-samples.py --isomer "./target/release/$(BINARY)"

# Install the pre-commit gate (no [patch] path overrides + make lint + make
# test). Bypass an individual commit with `git commit --no-verify`.
install-precommit:
	cp scripts/pre-commit "$$(git rev-parse --git-dir)/hooks/pre-commit"
	chmod +x "$$(git rev-parse --git-dir)/hooks/pre-commit"
	@echo "✓ Pre-commit hook installed."

clean:
	$(CARGO) clean

help:
	@echo "isomer targets:"
	@echo "  build     debug build"
	@echo "  release   optimized build"
	@echo "  install   cargo install to ~/.cargo/bin"
	@echo "  lint      rustfmt --check + clippy with warnings denied"
	@echo "  fix       auto-fix clippy + rustfmt"
	@echo "  test      run the test suite"
	@echo "  demo      detect every bundled supply-chain case, narrated"
	@echo "  validate-samples  audit before/during/after corpus for misses + false positives"
	@echo "  install-precommit  gate commits on lint + test"
	@echo "  clean     cargo clean"
