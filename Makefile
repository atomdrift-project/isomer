SHELL := /bin/sh
# isomer — supply-chain attack detection at a molecular level. The cargo bin,
# build artifact, and installed binary all share the name `isomer`.
BINARY = isomer

# Scrub GNU make's jobserver from cargo's environment, so build scripts that
# spawn their own `make` (e.g. tikv-jemalloc-sys, pulled in transitively via
# cleave) don't inherit a malformed MAKEFLAGS. Mirrors scan's Makefile.
CARGO = env -u MAKEFLAGS -u MAKELEVEL -u MFLAGS cargo

.PHONY: all build release install lint fix test demo clean help

all: build

build:
	$(CARGO) build

release:
	$(CARGO) build --release

install: release
	$(CARGO) install --path .

lint:
	$(CARGO) clippy -- -D warnings

# Auto-fix what clippy and rustfmt can fix on their own; fmt last.
fix:
	$(CARGO) clippy --fix --allow-dirty --allow-staged
	$(CARGO) fmt

test:
	$(CARGO) test --quiet

# Run the curated real-world supply-chain pairs and narrate each verdict.
# Builds once, then hands the release binary to the demo script so the
# narration isn't interleaved with cargo output.
demo: release
	@sh scripts/demo.sh "./target/release/$(BINARY)"

clean:
	$(CARGO) clean

help:
	@echo "isomer targets:"
	@echo "  build     debug build"
	@echo "  release   optimized build"
	@echo "  install   cargo install to ~/.cargo/bin"
	@echo "  lint      clippy with warnings denied"
	@echo "  fix       auto-fix clippy + rustfmt"
	@echo "  test      run the test suite"
	@echo "  demo      detect every bundled supply-chain case, narrated"
	@echo "  clean     cargo clean"
