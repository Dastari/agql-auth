# Migration Guide

## 0.8.0 to 0.8.1: omitted optional JWT claims

No source, configuration, or storage migration is required. `0.8.1` changes
only locally issued JWT serialization: unset optional top-level claims are
omitted instead of encoded as JSON `null`.

Hosts should not manufacture an `nbf` value to work around the `0.8.0` output.
When no not-before constraint is intended, the standards-conforming payload has
no `nbf` member. When `nbf` is present, it remains a NumericDate and existing
injected-clock/leeway validation applies unchanged.

Existing short-lived `0.8.0` tokens may continue to decode in compatible
consumers, but strict resource servers can reject their `"nbf": null` member.
Upgrade the issuer to `0.8.1` and let those tokens expire normally; no refresh
record or key migration is needed.

## 0.7 to 0.8: session assurance continuity

`0.8` adds authoritative session assurance without changing the
`RefreshTokenStore` trait methods. Existing issuance methods remain available
and issue no authoritative assurance unless the supplied `SessionContext`
contains one.

### Host code

Replace ad hoc MFA booleans or access-token-only claim plumbing with:

```rust
use agql_auth::{
    AuthMethod, MfaAcceptance, RefreshableTokenMetadata, SessionAssurance,
};

let assurance = SessionAssurance::new(
    verified_authentication_time,
    ["pwd", "otp"],
    Some(host_accepted_acr),
    Some("my-provider-policy-v1".to_string()),
    MfaAcceptance::Satisfied,
)?;

let payload = auth
    .issue_assured_user_session(
        user_id,
        roles,
        scopes,
        AuthMethod::Oidc,
        assurance,
        RefreshableTokenMetadata::default(),
        client_metadata,
    )
    .await?;
```

For OIDC, read `ValidatedOidcClaims.auth_time`, `.amr`, and `.acr` inside your
`ClaimsMapper`. Return `MappedClaims { assurance: Some(...) }` only after local
policy accepts the provider values. A missing value, `NoopClaimsMapper`, and
`MicrosoftClaimsMapper` all leave MFA unsatisfied.

### Refresh storage migration

`StoredRefreshToken` adds `refreshable_metadata: Option<RefreshableTokenMetadata>`.
`SessionContext`, already stored in the refresh record, adds optional
`assurance`. JSON/document stores can deploy the new reader first: both fields
use Serde defaults and missing values become `None`.

For relational stores, add nullable JSON columns (or equivalent typed columns):

```sql
ALTER TABLE refresh_tokens
    ADD COLUMN refreshable_metadata JSON NULL;

-- If session context is decomposed rather than stored as JSON, also add
-- nullable assurance timestamp, AMR, ACR, context, and MFA-acceptance fields.
```

Do not backfill old rows with the migration time. Leave assurance `NULL`.
Legacy sessions continue refreshing normally, but an opted-in
`RecentMfaPolicy` denies them until a genuine step-up occurs.

The store trait signatures did not change. Implementations that construct
`StoredRefreshToken` literals must add `refreshable_metadata: None`. This public
record and `MappedClaims`/`ValidatedOidcClaims` field addition is the reason for
the `0.7` to `0.8` SemVer bump.

### Refresh metadata decision

Only tenant ID, organization ID, actor, and correlation ID are refreshable.
Assurance is sourced from `SessionContext.assurance`. A new `jti`, expiry, and
purpose are generated for every access token. `cnf`, resource type/ID, and
arbitrary additional claims are not propagated because their validity may be
specific to one sender, resource, or token.

### Recent-MFA guard

```rust
use agql_auth::{AssuranceMatchMode, RecentMfaPolicy};
use time::Duration;

let policy = RecentMfaPolicy {
    maximum_age: Duration::minutes(10),
    clock_skew: Duration::seconds(30),
    allowed_amr: vec!["otp".into(), "hwk".into()],
    allowed_acr: vec!["urn:example:loa:2".into()],
    match_mode: AssuranceMatchMode::Any,
};

policy.evaluate(&authenticated_user, &clock).map_err(|denial| {
    // Return denial.code().as_str() and denial.public_message() to the client.
    // Send denial.internal_detail() only to protected server diagnostics.
    denial
})?;
```

At the exact maximum-age or future-skew boundary, the policy allows. One second
beyond either boundary denies. Missing/inconsistent claims and checked-time
overflow deny safely.

See [session assurance](docs/session-assurance.md) for trust boundaries,
step-up, and long-lived connection guidance.

## 0.6 to 0.7

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
| `AuthUser` struct construction | Structural/API break | add `token_claims: Default::default()` |
| GraphQL `ErrorExtensions` message text | Behavioral hardening | safe public message only; use `public_code()` |
| Access-token-only / custom access TTL | Behavioral bound | must be `<= AuthConfig::max_access_token_ttl` (24h default) |
| Hierarchical bare `*` wildcard | Behavioral opt-in | deny unless `allow_universal_wildcard = true` |
| `AccessTokenValidator` HS256 validation | Behavioral guard on new API | rejected unless `accept_hs256(true)` |
| `HierarchicalScopeMatch` | Behavioral opt-in | not used unless configured; exact remains default |
| `super_scopes` | Behavioral opt-in | empty by default |
| `CombinedAuth` token order | Behavioral opt-in | JWT-shaped first; expired JWT never falls back |
| `ChannelIdentity` / WebSocket reauth hooks | Additive | host-owned channel verify + optional status checks |

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
use time::Duration;

let grant = auth
    .issue_access_token_only(
        AccessTokenOnlyRequest::new(user_id, roles, scopes, session)
            .with_ttl(Duration::minutes(30)),
    )
    .await?;
```

This path never writes a refresh-token row. TTL must be positive and not exceed
`AuthConfig::max_access_token_ttl` (default 24 hours). Issued tokens include a
unique `jti` and `purpose = access_token`.

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

Canonical vectors are published in
[`testdata/scope_match_golden.json`](testdata/scope_match_golden.json).

| # | Granted | Required | Expected |
|---|---------|----------|----------|
| 1 | `a.b.c.d` | `a.b.c.d` | allow |
| 2 | `a.b.c.read` | `a.b.c.write` | deny |
| 3 | `a.b.*` | `a.b.c` | allow |
| 4 | `a.b.*` | `a.b.c.d` | allow |
| 5 | `a.b.*` | `a.bc.d` | deny |
| 6 | `a.b.*` | `a.b` | deny |
| 7 | `*` | `anything.at.all` | deny (default) |
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

Bare `*` is denied unless `allow_universal_wildcard = true`. Super-scopes remain
empty unless configured.

## Public GraphQL Errors

Before:

```text
message included OIDC/store internal detail strings
```

After:

```rust
assert_eq!(err.public_code(), "AUTH_SERVICE_UNAVAILABLE");
assert_eq!(err.public_message(), "authentication service unavailable");
// GraphQL ErrorExtensions uses only public_message + code
```

## AuthUser Construction

Add the new field (or rely on struct update / default in tests):

```rust
AuthUser {
    user_id,
    session_id,
    roles,
    scopes,
    session,
    token_claims: Default::default(),
}
```

## Access-Token-Only TTL Bound

Custom TTLs must be `<= AuthConfig::max_access_token_ttl` (default 24 hours).

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

## WebSocket Reauthorization Expectations

`0.7` does not take over your subscription transport. Hosts should:

1. Authenticate `connection_init` with
   `AccessTokenValidator::authenticate_connection_init_value` (or
   `AuthService::authenticate_connection_init_value`).
2. Treat missing connection-init credentials as unauthenticated and invalid
   tokens as fail-closed (never as anonymous).
3. Optionally implement `TokenStatusChecker` for session/`jti`/principal
   revocation on high-risk operations or periodic checks.
4. Use `ReauthorizationPolicy::next_deadline` with
   `AuthUser.token_claims.expires_at` to schedule reauthorization.
5. Keep the default failure mode fail-closed
   (`StatusCheckFailureMode::FailClosed`).

See [WebSocket reauthorization](docs/websocket-reauthorization.md).
