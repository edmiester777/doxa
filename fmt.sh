set -e
cargo clippy --fix --all --allow-dirty --tests
cargo clippy --workspace --all-features --tests -- -D warnings
for feat in router oidc native; do
  cargo clippy -p doxa-client --no-default-features --features "$feat" --tests -- -D warnings
done
# wasm-only code is invisible to a host build.
WASM="--target wasm32-unknown-unknown"
cargo clippy -p doxa-client -p doxa-ui --all-features $WASM -- -D warnings
cargo clippy -p doxa-ui --no-default-features $WASM -- -D warnings
for feat in react export forms oidc npm gallery native; do
  cargo clippy -p doxa-ui --no-default-features --features "$feat" $WASM -- -D warnings
done
cargo clippy -p shop-web -p shop-api -p site --lib $WASM -- -D warnings
# Code behind the native gates, as the page builds for each target.
for target in desktop ios; do
  DOXA_TARGET=$target cargo clippy -p doxa-ui --features native $WASM -- -D warnings
  DOXA_TARGET=$target cargo clippy -p shop-web --lib $WASM -- -D warnings
done
cargo +nightly fmt --all
cargo run -q -p doxa-fmt -- crates examples
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
