# JWT Signing And JWKS

`agql-auth` issues local JWT access tokens. The signing mode is configured on
`AuthConfig` and is enforced by local validation, GraphQL request injection, and
password-reset token validation.

## HS256 Compatibility

Existing users can keep using `AuthConfig::new(secret)`.

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

- `sub`
- `sid`
- `roles`
- `scopes`
- `ctx`
- `iss`
- `aud`
- `exp`
- `iat`
