# Key Rotation And JWKS

Resource servers must never accept a token solely because a matching key
happens to be present. Issuer, audience, algorithm allowlist, purpose, expiry,
`nbf`, and claim requirements still apply.

## Static PEM

```rust
use agql_auth::AccessTokenValidator;

let validator = AccessTokenValidator::builder()
    .issuer("agql-auth")
    .audience("orders-api")
    .rs256_public_pem(public_pem)
    .key_id("auth-key-2026-07")
    .allowed_algorithms([jsonwebtoken::Algorithm::RS256])
    .build()?;
```

## Static JWKS

```rust
let validator = AccessTokenValidator::builder()
    .issuer("agql-auth")
    .audience("orders-api")
    .jwks_json(jwks_json)
    .key_id("auth-key-2026-07")
    .build()?;
```

Multi-key JWKS documents require `key_id` at build time or token `kid`
resolution through the key set.

## Key Resolver Abstraction

```rust
use std::sync::Arc;
use agql_auth::{AccessTokenKeyResolver, KeyRefreshPolicy, RotatingJwksKeySet, StaticJwksKeySet};

let static_set = StaticJwksKeySet::from_jwks_json(&jwks)?;
let rotating = RotatingJwksKeySet::new(&jwks, KeyRefreshPolicy::default())?;

// Host refresh loop (your HTTPS client):
if rotating.begin_forced_refresh() {
    match fetch_jwks_over_https().await {
        Ok(doc) => { let _ = rotating.replace_jwks(&doc); }
        Err(_) => rotating.end_forced_refresh(),
    }
}
```

`RotatingJwksKeySet` provides:

- multiple active keys selected by `kid`
- overlapping rotation via document replace
- bounded cache lifetime metadata
- unknown-`kid` forced-refresh cooldown
- refresh stampede prevention (`begin_forced_refresh`)
- explicit stale-key policy (`UseStale` default, `Reject` opt-in)
- injectable clock for deterministic tests

Remote JWKS HTTP is intentionally not a core dependency. Hosts supply the HTTPS
client, timeouts, redirect limits, response-size limits, and content-type checks.

## Algorithm Policy

HS256 is rejected unless `accept_hs256(true)` is set. Algorithm is always
compared to the configured allowlist; it is never trusted from the token alone.
