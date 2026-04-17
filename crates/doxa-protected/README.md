# doxa-protected

Zeroize-on-drop string type with `[REDACTED]` `Debug`/`Display`/`Serialize` and an OpenAPI `format: password` schema. Framework-neutral with zero internal dependencies.

## Usage

```rust
use doxa_protected::ProtectedString;

// From any string type
let secret: ProtectedString = "sk-live-abc123".into();

// Safe everywhere — Debug, Display, Serialize all emit [REDACTED]
tracing::info!(?secret, "loaded config");  // logs [REDACTED]
println!("{secret}");                       // prints [REDACTED]
serde_json::to_string(&secret)?;           // serializes "[REDACTED]"

// Explicit, grep-able access
connect(secret.expose());
```

`ProtectedString` wraps `secrecy::SecretString` in an `Arc` for cheap cloning. The inner value is zeroized on drop when the last reference is released.

## Design

- **Never leaks by accident.** Every output path (`Debug`, `Display`, `Serialize`, `ToSchema`) emits `[REDACTED]`.
- **Explicit access.** `expose()` is the only way to read the inner value, making every secret-access site grep-able and auditable.
- **Cheap clones.** `Arc`-backed so passing secrets through middleware layers and extractors costs a reference count bump, not a copy.
- **OpenAPI-aware.** Implements `utoipa::ToSchema` with `format: password` so generated specs mark the field correctly.

## License

Apache 2.0
