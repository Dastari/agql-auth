# Migration Guide: 0.6 to 0.7

Upgrade recipe:

1. Upgrade the `agql-auth` pin to `0.7`.
2. Run `cargo build`.
3. Fix each compile error against the old-to-new table below.
4. Run your auth and authorization tests.
5. If you opt into hierarchical matching, run the golden vectors in this file
   against your host scope catalog.

## Compatibility Posture

`0.7` is a deliberate resource-server and authorization release. The default
runtime behavior remains exact scope matching. Hierarchical matching,
super-scopes, access-token-only grants, combined JWT/API-token injection, and
channel guards are opt-in APIs.

## Breaking-Change Classification

| Area | Classification | Default behavior |
|------|----------------|------------------|
| Existing `AuthService` construction | No structural break | unchanged |
| Existing `AuthUser::has_scope` helpers | No behavioral break | exact matching |
| Existing `RequireScope` guards without `AuthRuntime` | No behavioral break | exact matching |
| Previous MFA Rust enum type name | Structural/API break | rename to `MfaFactor`; serialized claims unchanged |
| `AccessTokenValidator` HS256 validation | Behavioral guard on new API | rejected unless `accept_hs256(true)` |
| `HierarchicalScopeMatch` | Behavioral opt-in | not used unless configured |
| `super_scopes` | Behavioral opt-in | empty by default |
| `CombinedAuth` token order | Behavioral opt-in | JWT-shaped first; expired JWT never falls back |
| `ChannelIdentity` | Additive | host must verify channel before injection |

No product scope names, tenant IDs, cookie policy, HTTP routing, SQL, or
certificate parsing is introduced by this release.

## Old To New API Table

| 0.6 pattern | 0.7 replacement |
|-------------|-----------------|
| Previous MFA `Totp` enum path | `MfaFactor::Totp` |
| Construct `AuthService` in every resource server only to validate JWTs | `AccessTokenValidator::builder()` |
| Share HS256 secret with resource servers | Prefer `rs256_public_pem` or `jwks_json`; use `accept_hs256(true)` only deliberately |
| Manually decode access-token claims with `jsonwebtoken` | `AccessTokenValidator::authenticate_bearer` |
| Manually inject a user JWT or API token on one endpoint | `CombinedAuth::new(&validator_or_auth, &api_tokens).inject_http_auth(...)` |
| Exact-only guard semantics | unchanged by default |
| Host-specific wildcard checks in resolvers | `HierarchicalScopeMatch` plus `AuthRuntime` |
| Issue session then revoke/ignore refresh token for short-lived grants | `AuthService::issue_access_token_only` |
| Ad-hoc channel metadata in request data | `ChannelIdentity` plus `RequireChannelScheme` |

## Before And After: MFA Type Rename

After:

```rust
use agql_auth::MfaFactor;

let methods = vec![MfaFactor::Totp];
```

Only the Rust type name changed. The `SessionContext` JSON claim still uses the
same `mfa.methods` field and `Totp` variant value.

## Before And After: Resource Server Validation

Before, resource servers often needed issuer stores or hand-rolled JWT decode:

```rust
let user = auth_service.authenticate_bearer(authorization_header)?;
```

After:

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

## Before And After: Combined User Or API Token

Before:

```rust
let request = auth.inject_http_auth(request, authorization_header).await?;
let request = api_tokens
    .inject_http_auth(request, authorization_header, metadata)
    .await?;
```

After:

```rust
use agql_auth::CombinedAuth;

let request = CombinedAuth::new(&validator, &api_tokens)
    .inject_http_auth(request, authorization_header, metadata)
    .await?;
```

Use `RequirePrincipalScope` and `principal_from_ctx` for resolvers that accept
either credential type.

## Before And After: Access-Token-Only Grant

Before:

```rust
let payload = auth
    .issue_session_for_user_with_scopes(user_id, roles, scopes, session, metadata)
    .await?;
auth.logout(&payload.refresh_token, true).await?;
```

After:

```rust
use agql_auth::AccessTokenOnlyRequest;

let grant = auth
    .issue_access_token_only(AccessTokenOnlyRequest {
        user_id,
        roles,
        scopes,
        session,
        ttl: Some(time::Duration::minutes(30)),
    })
    .await?;
```

This path never writes a refresh-token row.

## Hierarchical Scope Matching

Exact matching remains the default:

```rust
assert!(user.has_scope("orders.read"));
assert!(!user.has_scope("orders.*"));
```

Opt in explicitly:

```rust
use std::sync::Arc;
use agql_auth::{HierarchicalScopeMatch, HierarchicalScopeOptions};

let matcher = Arc::new(HierarchicalScopeMatch::new(HierarchicalScopeOptions {
    super_scopes: vec!["platform.admin".to_string()],
    ..Default::default()
}));

let validator = AccessTokenValidator::builder()
    .issuer("agql-auth")
    .audience("agql-auth-clients")
    .rs256_public_pem(public_key_pem)
    .scope_matcher(matcher)
    .build()?;
```

### Golden Vectors

| # | Granted | Required | Expected |
|---|---------|----------|----------|
| 1 | `a.b.c.d` | `a.b.c.d` | allow |
| 2 | `a.b.c.read` | `a.b.c.write` | deny |
| 3 | `a.b.*` | `a.b.c` | allow |
| 4 | `a.b.*` | `a.b.c.d` | allow |
| 5 | `a.b.*` | `a.bc.d` | deny |
| 6 | `a.b.*` | `a.b` | deny |
| 7 | `*` | `anything.at.all` | allow |
| 8 | `a.b*` | `a.bc` | allow |
| 9 | `a.*.d` | `a.c.d` | allow |
| 10 | `a.*.d` | `a.c.x.d` | deny |
| 11 | `a.*.d` | `a.d` | deny |
| 12 | `a.b.*.read` | `a.b.c.write` | deny |
| 13 | `a.b.*.read` | `a.b.c.read` | allow |
| 14 | `a.b.*` | `a.b.*` | allow |
| 15 | `a.b.*` | `a.b.*.read` | allow |
| 16 | `x.*` | `y.b.c` | deny |
| 17 | `a.b.c.read` | `a.*.c.read` | deny |
| 18 | `a.b.c.d` | `a.b.c.d.e` | deny |
| 19 | empty granted set | `a.b.c` | deny |
| 20 | `a.b.c.read` | `a.b.c.read.extra` | deny |

Rows 7 and 8 are legacy-compatible hierarchical matcher behavior. Hosts that
do not want bare-star universal grants or raw partial-prefix grants should not
issue those grants or should provide a custom `ScopeMatch`.

## Channel Identity

`ChannelIdentity` is a bag for host-verified channel data:

```rust
use agql_auth::{ChannelIdentity, RequireChannelScheme};

let request = request.data(ChannelIdentity::new("mtls", "device-1"));

#[Object]
impl Mutation {
    #[graphql(guard = "RequireChannelScheme::new(\"mtls\")")]
    async fn device_action(&self) -> bool {
        true
    }
}
```

The host owns all channel verification.
