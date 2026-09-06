[private]
default:
    @just --list

# Build the release binary.
build:
    cargo build --release --locked

# Check Rust formatting and lint all targets.
check:
    cargo fmt --check
    cargo clippy --all-targets --locked -- -D warnings

# Run the Rust tests without network privileges.
test-rust:
    cargo test --locked

# Run privileged Rust network tests; accepts Rust test filters and options.
[positional-arguments]
test-network *args:
    mkdir -p tests/artifacts
    cargo test --locked --test network --config 'target."cfg(target_os = \"linux\")".runner = ["sudo", "--preserve-env=NDP_TEST_BINARY,NDP_TEST_ARTIFACTS"]' -- --ignored --test-threads=1 "$@"

# Build and validate the Nix package and module locally.
check-nix:
    nix flake check

# Build the package in a prepared Debian 13 environment.
deb:
    cargo deb --locked
