# Key Rotation And JWKS

Resource servers must never accept a token solely because a matching key
happens to be present. Issuer, audience, algorithm allowlist, purpose, expiry,
`nbf`, and claim requirements still apply.

## Rotating The Issuer's Signing Key

`AuthService` signs with one RS256 key and can also hold up to
`MAX_PREVIOUS_VERIFICATION_KEYS` (8) verification-only previous keys. A
previous key is published by `jwks()` and accepted by the service's own
validation (access tokens, purpose tokens, password-reset tokens) when a
token's header `kid` names it. It is never used to sign.

```rust
use agql_auth::AuthConfig;

let config = AuthConfig::with_rs256_pem(new_private_pem, new_public_pem, "auth-key-2026-11")
    .with_previous_verification_key("auth-key-2026-07", old_public_pem);
```

Procedure, with `T` = the longest lifetime of anything the old key signed: the
access-token maximum (`max_access_token_ttl`, which also bounds ordinary
sessions), the longest purpose-token and password-reset TTL you issue, plus
validator leeway:

1. Generate the new key pair with a new `kid`.
2. Publish the new public key before anyone signs with it. Either deploy the
   issuer with the new key as a previous key while still signing with the old
   one, or add it to the JWKS document your resource servers load. Wait until
   every resource server has refreshed its JWKS (at least the JWKS cache TTL).
3. Switch signing: configure the new key as the signing key and the old public
   key in `previous_verification_keys`. Roll this out to every issuer
   instance; during the rollout instances signing with either key validate
   each other's tokens.
4. Wait `T`. Tokens signed with the old key expire.
5. Remove the old key from `previous_verification_keys` and redeploy. It
   disappears from `jwks()`; resource servers drop it on their next refresh.

Skipping step 2 makes resource servers reject new tokens until they refresh.
Skipping step 3's previous key makes the cutover hard: every unexpired token
signed with the old key fails at once. To withdraw a compromised key, skip the
wait and remove it immediately; tokens it signed then fail everywhere once
resource servers refresh.

HS256 has no previous-key support: the secret cannot be published and HS256
tokens carry no `kid`. A previous key with HS256 signing is a configuration
error.

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

A PEM holds one key, so it cannot span a rotation. Use a JWKS document for
overlap.

## Static JWKS

```rust
let validator = AccessTokenValidator::builder()
    .issuer("agql-auth")
    .audience("orders-api")
    .jwks_json(jwks_json)
    .build()?;
```

`kid` handling:

- A multi-key document resolves each token by its header `kid`, so a document
  with the outgoing and incoming keys accepts both. Every key needs a unique
  `kid`; tokens without one are rejected.
- A one-key document whose JWK has a `kid` requires tokens to carry that `kid`.
  A one-key document without a `kid` accepts only tokens without one.
- `key_id(..)` optionally pins one accepted `kid`; `key_ids([..])` pins a set,
  for example both keys during an overlap. Every pinned `kid` must be in the
  document.

Each key keeps its own algorithm: the JWK `alg`, or, when absent, RS256 for
RSA, ES256 for EC P-256, ES384 for EC P-384 and EdDSA for Ed25519. A key only
verifies tokens whose header `alg` equals its algorithm. The validator's
allowlist defaults to RS256; add other algorithms with `allowed_algorithms`.
Parsing refuses symmetric (`oct`) keys, HMAC or encryption `alg` values,
duplicate `kid`s and unidentified keys in a multi-key document. Keys whose
`use` is not `sig` are skipped.

## Rotating JWKS Set

```rust
use std::sync::Arc;
use agql_auth::{KeyRefreshPolicy, RotatingJwksKeySet};

let rotating = Arc::new(RotatingJwksKeySet::new(&jwks, KeyRefreshPolicy::default())?);
let validator = AccessTokenValidator::builder()
    .issuer("agql-auth")
    .audience("orders-api")
    .key_resolver(rotating.clone())
    .build()?;

// Periodic refresh (your HTTPS client), for example every minute:
if rotating.needs_refresh() {
    if let Ok(doc) = fetch_jwks_over_https().await {
        let _ = rotating.replace_jwks(&doc);
    }
}

// Unknown kid: refresh at most once per cooldown, stampede-safe.
if rotating.should_force_refresh_for_unknown_kid() && rotating.begin_forced_refresh() {
    match fetch_jwks_over_https().await {
        Ok(doc) => { let _ = rotating.replace_jwks(&doc); }
        Err(_) => rotating.end_forced_refresh(),
    }
}
```

`RotatingJwksKeySet` provides:

- multiple active keys selected by `kid`, with the static JWKS rules above
- overlapping rotation via document replace
- `needs_refresh()` once the cache is older than `cache_ttl`
- unknown-`kid` forced-refresh cooldown and stampede prevention
- a bounded stale-key policy
- injectable clock for deterministic tests

`KeyRefreshPolicy::default()` is `cache_ttl` 5 minutes, `unknown_kid_cooldown`
30 seconds, `stale_policy = UseStale` and `max_stale` 1 hour. Under `UseStale`
the last loaded keys keep verifying for `max_stale` after `cache_ttl` while
refreshes fail, then every token is rejected with `AuthServiceUnavailable`
until a refresh succeeds. This keeps a JWKS outage from failing all traffic at
once while bounding how long a withdrawn key keeps working. `Reject` fails as
soon as `cache_ttl` passes, for deployments whose refresher always runs ahead of
the TTL. Either way the host must refresh periodically; a set that is never
refreshed stops verifying after `cache_ttl + max_stale`.

Before 0.27 the default was `Reject` with no stale window, so following the
example above without a periodic refresh failed every token 5 minutes after
load.

Remote JWKS HTTP is intentionally not a core dependency. Hosts supply the HTTPS
client, timeouts, redirect limits, response-size limits, and content-type checks.

## Algorithm Policy

HMAC (HS256, HS384, HS512) is rejected unless `accept_hs256(true)` is set, on
every path: an `hs256_secret`, an HMAC algorithm in `allowed_algorithms`, and an
HMAC key returned by a custom `key_resolver`, whether at build time or for a
single request. Algorithm is always compared to the configured allowlist and to
the resolved key's own algorithm; it is never trusted from the token alone.
