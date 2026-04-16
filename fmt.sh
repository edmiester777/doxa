cargo clippy --fix --all --allow-dirty --tests && \
cargo +nightly fmt --all && \
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
