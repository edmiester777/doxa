cargo clippy --fix --all --allow-dirty --tests && \
cargo +nightly fmt --all && \
cargo run -q -p doxa-fmt -- crates examples && \
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
