SHELL := /bin/sh
# isomer — supply-chain attack detection at a molecular level. The cargo bin,
# build artifact, and installed binary all share the name `isomer`.
BINARY = isomer

# Scrub GNU make's jobserver from cargo's environment, so build scripts that
# spawn their own `make` (e.g. tikv-jemalloc-sys, pulled in transitively via
# cleave) don't inherit a malformed MAKEFLAGS. Mirrors scan's Makefile.
CARGO = env -u MAKEFLAGS -u MAKELEVEL -u MFLAGS cargo

# Cargo package name, which is not always the binary name (scan's package is
# `atomdrift-scan` but ships `atomscan`). Read from Cargo.toml so `cut-release`
# passes the right `-p` without a second place to keep in sync.
PACKAGE := $(shell awk -F'"' '/^name = /{print $$2; exit}' Cargo.toml)

.PHONY: all build release quick install lint fix test demo validate-samples install-precommit cut-release clean help

# Trait set the sample audit judges with. Defaults to the working-tree
# traits-dev beside this repo when present, so the audit tracks trait edits;
# override CLEAVE_TRAITS_DIR to point elsewhere (or leave unset for bundled).
TRAITS_DIR ?= $(if $(wildcard ../traits-dev/.),../traits-dev,)

all: build

build:
	$(CARGO) build

release:
	$(CARGO) build --release

# Optimized but un-LTO'd, for targets that build then immediately run the
# binary. See [profile.quick] in Cargo.toml.
quick:
	$(CARGO) build --profile quick

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

# Run the curated real-world supply-chain attacks — command in, verdict out,
# nothing else. Doubles as a smoke test: fails if any case drops below notable.
# Builds once, then hands the binary to the demo script so the output isn't
# interleaved with cargo's.
demo: quick
	@sh scripts/demo.sh "./target/quick/$(BINARY)"

# Self-audit against the supply-chain corpus: for every attack, before->during
# must be detected, and during->after / before->after must not. Prints a
# violations report and exits non-zero on any miss or false positive. Point at
# the corpus with ISOMER_SAMPLES_DIR (default ~/src/supplychain-attack-data);
# it skips cleanly (exit 2) when the corpus is absent.
validate-samples: quick
	@CLEAVE_TRAITS_DIR="$(TRAITS_DIR)" \
		python3 scripts/validate-samples.py --isomer "./target/quick/$(BINARY)"

# Install the pre-commit gate (no [patch] path overrides + make lint + make
# test). Bypass an individual commit with `git commit --no-verify`.
install-precommit:
	cp scripts/pre-commit "$$(git rev-parse --git-dir)/hooks/pre-commit"
	chmod +x "$$(git rev-parse --git-dir)/hooks/pre-commit"
	@echo "✓ Pre-commit hook installed."

# Cut a release: set the version everywhere it is recorded, prove the result
# builds the way CI will, and commit + tag it as one unit.
#
#     make cut-release VERSION=0.5.0
#
# The version lives in three places that must agree — Cargo.toml, Cargo.lock,
# and the tag — and release.yml rejects the build if any pair disagrees. Doing
# it by hand cost four failed release runs in one day: a tag ahead of
# Cargo.toml, then Cargo.toml ahead of Cargo.lock, each discovered ~40 minutes
# into a matrix that `cargo check --locked` disproves in seconds.
#
# Pushing stays manual on purpose. That is the step that spends an hour of CI
# and publishes artifacts people download, so it gets a human; everything this
# target does is local and revertible with `git reset --hard HEAD~1` plus
# `git tag -d`.
cut-release:
	@test -n "$(VERSION)" || { echo "usage: make cut-release VERSION=x.y.z" >&2; exit 1; }
	@printf '%s\n' "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$$' \
		|| { echo "VERSION must look like 1.2.3 (got '$(VERSION)')" >&2; exit 1; }
	@test -z "$$(git status --porcelain)" \
		|| { echo "working tree is dirty — the tag must capture exactly what was tested:" >&2; \
		     git status --short >&2; exit 1; }
	@if git rev-parse -q --verify "refs/tags/v$(VERSION)" >/dev/null; then \
		echo "tag v$(VERSION) already exists" >&2; exit 1; fi
	@# Rewrite only the first `version =`, which is the one in [package].
	@awk -v v="$(VERSION)" 'BEGIN{d=0} /^version = "/ && !d {print "version = \"" v "\""; d=1; next} {print}' \
		Cargo.toml > Cargo.toml.tmp && mv Cargo.toml.tmp Cargo.toml
	$(CARGO) update -p $(PACKAGE) --offline
	@# The exact gate release.yml applies, minus the hour of linking.
	$(CARGO) check --locked --all-targets
	git add Cargo.toml Cargo.lock
	git commit -m "v$(VERSION)"
	git tag -a "v$(VERSION)" -m "$(BINARY) $(VERSION)"
	@echo
	@echo "tagged v$(VERSION). to release:"
	@echo "    git push origin $$(git rev-parse --abbrev-ref HEAD) && git push origin v$(VERSION)"

clean:
	$(CARGO) clean

help:
	@echo "isomer targets:"
	@echo "  build     debug build (optimized dependencies)"
	@echo "  release   optimized build"
	@echo "  quick     optimized build, no LTO — fast to link, used by demo"
	@echo "  install   cargo install to ~/.cargo/bin"
	@echo "  lint      rustfmt --check + clippy with warnings denied"
	@echo "  fix       auto-fix clippy + rustfmt"
	@echo "  test      run the test suite"
	@echo "  demo      detect every bundled supply-chain case, narrated"
	@echo "  validate-samples  audit before/during/after corpus for misses + false positives"
	@echo "  install-precommit  gate commits on lint + test"
	@echo "  cut-release  bump version + lockfile, verify, commit, tag (VERSION=x.y.z)"
	@echo "  clean     cargo clean"
