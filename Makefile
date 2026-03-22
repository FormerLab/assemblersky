# Assemblersky — build the CLI harness
# Requires: nasm, rust/cargo, cc

ROOT := $(shell pwd)

.PHONY: all build test clean

all: build

build:
	cd rust-harness && ASB_ROOT=$(ROOT) cargo build --release
	@echo "Built: rust-harness/target/release/assemblersky-harness"

test: build
	rust-harness/target/release/assemblersky-harness \
		--input tests/fixtures/relay_commit_frame.bin \
		| python3 -m json.tool

clean:
	cd rust-harness && cargo clean
