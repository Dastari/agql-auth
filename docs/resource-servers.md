# Resource Servers

`AccessTokenValidator` validates local `agql-auth` access tokens without
`UserStore` or `RefreshTokenStore`. Use it in APIs, subgraphs, workers, and
routers that only need to authenticate bearer JWTs issued by an `AuthService`.

## Issuer And Validator Topology

The issuer owns password login, refresh-token rotation, OIDC handoff, and token
signing:

```rust
use std::sync::Arc;
use agql_auth::{AuthConfig, AuthService};

let auth = AuthService::new(
    AuthConfig::with_rs256_pem(private_key_pem, public_key_pem, "auth-key-2026-07"),
    Arc::new(user_store),
    Arc::new(refresh_token_store),
)?;
```

Resource servers only need public validation material:

```rust
use agql_auth::AccessTokenValidator;

let validator = AccessTokenValidator::builder()
    .issuer("agql-auth")
    .audience("agql-auth-clients")
    .rs256_public_pem(public_key_pem)
    .key_id("auth-key-2026-07")
    .build()?;
```

`AuthService` and `AccessTokenValidator` share one decode core and agree on the
access-token claim shape: `typ`, `purpose`, `iss`, `aud`, `sub`, `sid`, `roles`,
standard `scope`, `ctx`, `exp`, `iat`, optional `nbf`, and optional multi-tenant metadata
(`jti`, `tenant_id`, `organization_id`, `session_family_id`, `actor`, `auth_time`,
`amr`, `acr`, `cnf`, resource binding, `correlation_id`). New access tokens carry
`typ = "access"`, `purpose = "access_token"`, and a unique `jti`. Legacy tokens
missing purpose still validate under the default purpose policy. The pre-0.14
`scopes` array is accepted by default during migration; see
[Access-token scope claims](access-token-scope-claims.md).

## Validation Policy Highlights

- RS256 by default; explicit algorithm allowlist via `allowed_algorithms`
- Issuer and audience validation (including multi-audience tokens)
- Expiry and `nbf` checks with configurable bounded clock skew (`leeway_seconds`, max 300)
- Injectable clock for deterministic tests
- Expected `kid` where configured; multi-key JWKS resolves by token `kid`
- HS256 only with `accept_hs256(true)`
- Purpose policy: `AccessTokenOrLegacy` (default) or `RequireAccessToken`
- Legacy scope policy: `Accept` (default migration mode) or `Reject`
- Claim requirements via `ClaimRequirements`
- Bearer parse mode: `BearerOrRaw` (default) or `RequireBearer`
- Basic and other schemes are rejected
- Missing auth is distinguishable from invalid auth; invalid never becomes anonymous

## Static JWKS JSON

If the host already distributes a JWKS document, use static JWKS JSON:

```rust
let validator = AccessTokenValidator::builder()
    .issuer("agql-auth")
    .audience("agql-auth-clients")
    .jwks_json(jwks_json)
    .key_id("auth-key-2026-07")
    .build()?;
```

For a multi-key JWKS, `key_id` is required. For a one-key JWKS, the validator
uses that key and requires the token `kid` when the JWK includes one.

## HS256 Gate

HS256 validation is disabled for resource servers unless explicitly enabled:

```rust
let validator = AccessTokenValidator::builder()
    .issuer("agql-auth")
    .audience("agql-auth-clients")
    .accept_hs256(true)
    .hs256_secret(secret)
    .build()?;
```

This keeps symmetric secrets out of multi-service resource-server deployments
unless the host makes that tradeoff deliberately.

## Request Injection

`inject_http_auth` leaves missing authorization unchanged and rejects invalid
tokens. On success it inserts `AuthUser`, `AuthPrincipal::User`, and
`AuthRuntime`:

```rust
let request = validator.inject_http_auth(graphql_request, authorization_header)?;
```

Use `authenticate_connection_init_value` for GraphQL WebSocket payloads:

```rust
let user = validator.authenticate_connection_init_value(
    &payload,
    &["WsAuthorization", "Authorization"],
)?;
```

## Scope Matcher

Attach a matcher to the validator so guards use the same scope semantics as the
resource-server authentication path:

```rust
use std::sync::Arc;
use agql_auth::{HierarchicalScopeMatch, HierarchicalScopeOptions};

let validator = AccessTokenValidator::builder()
    .issuer("agql-auth")
    .audience("agql-auth-clients")
    .rs256_public_pem(public_key_pem)
    .scope_matcher(Arc::new(HierarchicalScopeMatch::new(
        HierarchicalScopeOptions {
            super_scopes: vec!["platform.admin".to_string()],
            ..Default::default()
        },
    )))
    .build()?;
```

Exact matching remains the default.

After all pre-0.14 access tokens have expired, disable the legacy array on each
resource server independently:

```rust
use agql_auth::LegacyScopeClaims;

let validator = AccessTokenValidator::builder()
    // issuer, audience, and public-key configuration
    .legacy_scope_claims(LegacyScopeClaims::Reject)
    .build()?;
```
