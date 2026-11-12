# Secrets

Somebody, someday, will `tracing::info!(?config)`. Make sure it's boring when they do.

```rust
use doxa::protected::ProtectedString;

#[derive(Deserialize)]
struct Config {
    api_key: ProtectedString,
}

let cfg: Config = serde_yaml::from_str("api_key: sk-live-abc123").unwrap();
tracing::info!(?cfg, "loaded");     // api_key: [REDACTED]
connect(cfg.api_key.expose());      // explicit, and easy to grep for
```

## What you get

- `Debug`, `Display` and `Serialize` all print `[REDACTED]`. Deserializing still reads the real value, so config files just work.
- The memory is zeroed on drop.
- Its OpenAPI schema is `format: password`, so docs and generated clients treat it as one.
- The only way to the value is `.expose()`. Every place that reads a secret is one search away.

It's the `protected` feature, and it works without the rest of doxa.
