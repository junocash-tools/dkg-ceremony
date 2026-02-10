BIN := bin/dkg-ceremony

.PHONY: build
build:
	cargo build --release
	mkdir -p bin
	cp target/release/dkg-ceremony $(BIN)

.PHONY: test test-unit test-e2e
test: test-unit test-e2e

test-unit:
	cargo test

test-e2e:
	cargo test --test e2e_txsign_ext -- --ignored

.PHONY: fmt
fmt:
	cargo fmt

.PHONY: lint
lint:
	cargo clippy -- -D warnings
