# JWT Signing And JWKS

`agql-auth` issues local JWT access tokens and short-lived purpose tokens. The
signing mode is configured on `AuthConfig` and is enforced by local validation,
GraphQL request injection, password-reset token validation, and purpose-token
validation.

## HS256 Compatibility

Existing users can keep using `AuthConfig::new(secret)`, but `0.6.0` and later require
the HS256 secret to be at least 32 bytes.

```rust
use std::sync::Arc;
use agql_auth::{AuthConfig, AuthService};

let auth = AuthService::new(
    AuthConfig::new(std::env::var("JWT_SECRET")?),
    Arc::new(user_store),
    Arc::new(refresh_token_store),
)?;
```

This signs and validates tokens with HS256 and a shared secret. It is useful for
simple deployments and backward compatibility, but it is not recommended when
external routers need to validate tokens. Sharing a symmetric signing secret
with multiple systems increases blast radius.

`AuthConfig::with_hs256_secret(secret)` is equivalent and can be used when the
signing mode should be explicit.

`AuthConfig.jwt_secret` remains public for source compatibility, but it is now a
legacy mirror. `AuthConfig.jwt_signing` is authoritative; use
`set_jwt_signing` instead of mutating `jwt_secret` directly.

## RS256

Use RS256 when the auth service should sign tokens and other systems should
validate those tokens with public key material.

```rust
use std::sync::Arc;
use agql_auth::{AuthConfig, AuthService};

let auth = AuthService::new(
    AuthConfig::with_rs256_pem(
        std::env::var("JWT_PRIVATE_KEY_PEM")?,
        std::env::var("JWT_PUBLIC_KEY_PEM")?,
        "auth-key-2026-06",
    ),
    Arc::new(user_store),
    Arc::new(refresh_token_store),
)?;
```

RS256 behavior:

- access tokens use `alg = RS256`
- access-token headers include the configured `kid`
- private key material is used only for signing
- public key material is used for local validation and JWKS export
- issuer, audience, expiry, roles, scope values, and session claims are
  independent of the signing algorithm
- incoming token headers must match the configured algorithm
- incoming RS256 tokens must contain the expected `kid`

The service parses and validates key material during `AuthService::new`, so
invalid PEM, empty key IDs, and mismatched keys fail fast.

## JWKS Export

Host applications can expose public signing keys through their own framework:

```rust
async fn jwks(
    auth: axum::extract::State<AuthState>,
) -> Result<axum::Json<serde_json::Value>, AppError> {
    Ok(axum::Json(auth.service.jwks()?))
}
```

For RS256, `auth.jwks()` returns:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "auth-key-2026-06",
      "n": "...",
      "e": "..."
    }
  ]
}
```

No private key fields are included.

For HS256, JWKS export returns `AuthError::JwksUnsupported`. A symmetric secret
is not public key material and should not be exposed as JWKS.

## Store-Free Resource-Server Validation

Use `AccessTokenValidator` when a service needs to validate local access tokens
but should not own user or refresh-token stores:

```rust
use agql_auth::AccessTokenValidator;

let validator = AccessTokenValidator::builder()
    .issuer("agql-auth")
    .audience("agql-auth-clients")
    .rs256_public_pem(public_key_pem)
    .key_id("auth-key-2026-07")
    .build()?;

let user = validator.authenticate_bearer(authorization_header)?;
```

Static JWKS JSON is also supported:

```rust
let validator = AccessTokenValidator::builder()
    .issuer("agql-auth")
    .audience("agql-auth-clients")
    .jwks_json(jwks_json)
    .key_id("auth-key-2026-07")
    .build()?;
```

HS256 resource-server validation requires explicit opt-in:

```rust
let validator = AccessTokenValidator::builder()
    .issuer("agql-auth")
    .audience("agql-auth-clients")
    .accept_hs256(true)
    .hs256_secret(secret)
    .build()?;
```

See [Resource servers](resource-servers.md).

## Production Posture

For router or external-service validation:

- prefer RS256 or another future asymmetric mode
- keep the private key only in the auth service
- expose only the public JWKS document
- configure routers with issuer, audience, algorithm, and JWKS URL
- rotate keys by changing `kid`

This version exposes one active RS256 public key. During future multi-key
rotation support, publish both old and new public keys while old tokens can
still be valid.

## Claims Shape

Changing signing modes does not rename or remove access-token claims. Version
0.14 access tokens use the standard OAuth `scope` string:

- `typ`
- `sub`
- `sid`
- `roles`
- `scope`
- `ctx`
- `iss`
- `aud`
- `exp`
- `iat`

During a bounded migration, validation also accepts the pre-0.14 `scopes`
array. Issuers can temporarily retain that format, and validators can reject it
after every old access token has expired. See
[Access-token scope claims](access-token-scope-claims.md). Purpose tokens remain
separate and continue using their `scopes` array.

`0.6.0` added `typ = "access"` and `purpose = "access_token"` to newly issued
access tokens. Validation accepts legacy `0.5.x` access tokens that do not
contain those claims, but rejects any token whose `typ` or `purpose` is present
and not the access-token value.

Access tokens are stateless and remain valid until `exp`, even after logout or
refresh-token-family revocation. Keep access-token TTLs short, and use the
embedded `sid` for host-side session checks on high-risk resolvers if your app
needs immediate session revocation.

## Purpose Tokens

Purpose tokens are short-lived JWTs for narrow non-session grants, such as a
mobile upload grant or a one-off capture grant. They are signed with the same
configured HS256 or RS256 key material but are structurally separated from
access tokens:

- `typ = "purpose_token"`
- exact `purpose` validation
- exact `aud` validation chosen by the caller
- optional `sid`, `scopes`, and custom flattened claims

```rust
use agql_auth::{PurposeTokenIssueRequest, PurposeTokenValidation};
use serde_json::json;
use time::Duration;

let issued = auth.issue_purpose_token(
    PurposeTokenIssueRequest::new(
        user_id,
        "capture_upload",
        "capture-upload-clients",
        Duration::minutes(15),
    )
    .with_session_id(session_id)
    .with_scopes(["collection.collection-1.records.create"])
    .with_claim("collectionId", json!(collection_id)),
)?;

let verified = auth.authenticate_purpose_token(
    &issued.token,
    PurposeTokenValidation::new("capture_upload", "capture-upload-clients"),
)?;
```

Do not validate purpose tokens with `authenticate_access_token`; access-token
validation rejects `typ = "purpose_token"`. Custom claims may not use reserved
claim names such as `sub`, `aud`, `exp`, `typ`, or `purpose`.

## Access-Token-Only Grants

`issue_access_token_only` issues a normal access JWT with no refresh-token row:

```rust
use agql_auth::{AccessTokenOnlyRequest, AuthMethod, SessionContext};
use time::Duration;

let grant = auth
    .issue_access_token_only(AccessTokenOnlyRequest {
        user_id: user_id.to_string(),
        roles: vec!["Device".to_string()],
        scopes: vec!["devices.read".to_string()],
        session: SessionContext::for_auth_method(AuthMethod::ServiceToken),
        ttl: Some(Duration::minutes(30)),
    })
    .await?;
```

The token validates through `AuthService::authenticate_access_token` and
`AccessTokenValidator::authenticate_access_token` exactly like a normal session
access token. It cannot be refreshed.

## RSA Advisory Note

This crate currently depends on `rsa` to parse RSA public keys for JWKS
modulus/exponent extraction. The known Marvin advisory for `rsa 0.9` is about
private-key timing side channels; `agql-auth` directly uses it for public-key
parsing/JWKS export, while signing and verification are handled by
`jsonwebtoken`.

Downstream `cargo audit` may still flag the dependency. Future work is to
evaluate replacing the direct `rsa` usage with lower-level DER/SPKI parsing or
a patched alternative.
