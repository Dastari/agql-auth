# JWT Signing And JWKS

`agql-auth` issues local JWT access tokens and short-lived purpose tokens. The
signing mode is configured on `AuthConfig` and is enforced by local validation,
GraphQL request injection, password-reset token validation, and purpose-token
validation.

## HS256 Compatibility

Existing users can keep using `AuthConfig::new(secret)`, but `0.6.0` requires
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
- issuer, audience, expiry, roles, scopes, and session claims are unchanged
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

Changing signing modes does not rename or remove access-token claims:

- `typ`
- `sub`
- `sid`
- `roles`
- `scopes`
- `ctx`
- `iss`
- `aud`
- `exp`
- `iat`

`0.6.0` adds `typ = "access"` and `purpose = "access_token"` to newly issued
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
        "mobile_capture",
        "digitise-mobile-capture",
        Duration::minutes(15),
    )
    .with_session_id(session_id)
    .with_scopes(["collection.collection-1.records.create"])
    .with_claim("collectionId", json!(collection_id)),
)?;

let verified = auth.authenticate_purpose_token(
    &issued.token,
    PurposeTokenValidation::new("mobile_capture", "digitise-mobile-capture"),
)?;
```

Do not validate purpose tokens with `authenticate_access_token`; access-token
validation rejects `typ = "purpose_token"`. Custom claims may not use reserved
claim names such as `sub`, `aud`, `exp`, `typ`, or `purpose`.

## RSA Advisory Note

This crate currently depends on `rsa` to parse RSA public keys for JWKS
modulus/exponent extraction. The known Marvin advisory for `rsa 0.9` is about
private-key timing side channels; `agql-auth` directly uses it for public-key
parsing/JWKS export, while signing and verification are handled by
`jsonwebtoken`.

Downstream `cargo audit` may still flag the dependency. Future work is to
evaluate replacing the direct `rsa` usage with lower-level DER/SPKI parsing or
a patched alternative.
