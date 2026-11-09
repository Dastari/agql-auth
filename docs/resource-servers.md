# Resource Servers

`AccessTokenValidator` validates local `agql-auth` access tokens without
`UserStore` or `RefreshTokenStore`. Use it in APIs, subgraphs, workers, and
routers that only need to authenticate bearer JWTs issued by an `AuthService`.

Transport expiry scheduling must use the same time basis as validation. Read
`validator.current_time()` to observe its retained injected clock on each check;
do not substitute system time when a custom clock is configured. The accessor
returns `time::OffsetDateTime` without authenticating or consulting current
account/session status. Validate target clock conversions and deny unsupported
values rather than falling back to a different clock.

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
`typ = "access"`, `purpose = "access_token"`, and a unique `jti`; every token
issued since 0.6.0 carries `typ` and `purpose`, and the validator requires both
by default. The pre-0.14 `scopes` array is rejected by default; see
[Access-token scope claims](access-token-scope-claims.md).

## Validation Policy Highlights

- RS256 by default; explicit algorithm allowlist via `allowed_algorithms`
- Issuer and audience validation (including multi-audience tokens)
- Expiry and `nbf` checks with configurable bounded clock skew (`leeway_seconds`, max 300)
- Injectable clock for deterministic tests
- Optional `kid` pin (`key_id` or `key_ids`); JWKS keys resolve by token `kid`
- Each key verifies only its own algorithm
- HMAC (HS256/384/512) only with `accept_hs256(true)`, including keys from a
  custom `key_resolver`
- Purpose policy: `RequireAccessToken` (default; requires `typ` and `purpose`)
  or the legacy opt-in `AccessTokenOrLegacy`
- Legacy scope policy: `Reject` (default) or the migration opt-in `Accept`
- Claim requirements via `ClaimRequirements`; `require_cnf` verifies the
  presented certificate or key (see
  [Multi-tenant claims](multi-tenant-claims.md#confirmation-cnf-binding))
- Bearer parse mode: `RequireBearer` (default) or the legacy opt-in
  `BearerOrRaw`; it also applies to WebSocket `connection_init` values
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

A multi-key JWKS resolves each token by its `kid`, so it can hold the outgoing
and incoming keys during a rotation. `key_id` / `key_ids` optionally pin the
accepted `kid`s. For a one-key JWKS, the validator uses that key and requires
the token `kid` when the JWK includes one. See [Key rotation](key-rotation.md).

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

Use `inject_http_auth_with_confirmation` instead when the host verified a
client certificate or proof-of-possession key for the request.

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
        HierarchicalScopeOptions::default()
            .with_super_scopes(["platform.admin"])
            .with_exact_only_scopes(["payments.credentials.release"]),
    )?))
    .build()?;
```

Exact matching remains the default.

The legacy array is rejected by default. Re-enable it only while an issuer
still emits it:

```rust
use agql_auth::LegacyScopeClaims;

let validator = AccessTokenValidator::builder()
    // issuer, audience, and public-key configuration
    .legacy_scope_claims(LegacyScopeClaims::Accept)
    .build()?;
```

## Upgrading To 0.27 Defaults

0.27 tightens three validator defaults: `typ`/`purpose` are required, the
`Bearer` scheme is required, and the legacy `scopes` array is rejected. A 0.26
issuer already mints `typ`, `purpose` and the standard `scope` on every access
token (unless it was explicitly configured with
`AccessTokenScopeClaimFormat::LegacyArray`), so resource servers can upgrade
before, after or alongside issuers. Order:

1. Confirm every client sends `Authorization: Bearer <token>` (and
   `"Bearer <token>"` in WebSocket `connection_init` values). Otherwise set
   `.bearer_parse_mode(BearerParseMode::BearerOrRaw)` before upgrading.
2. If any issuer uses `LegacyArray`, either switch it to `Standard` and wait
   out the maximum access-token TTL first, or set
   `.legacy_scope_claims(LegacyScopeClaims::Accept)` on validators.
3. Only an issuer older than 0.6 mints tokens without `typ`/`purpose`; keep
   `.purpose_policy(PurposePolicy::AccessTokenOrLegacy)` while one is running.
4. Upgrade resource servers, then issuers (or in either order when steps 1 to
   3 hold).

Access-token time claims must fit the supported `time::OffsetDateTime` range.
Out-of-range signed `exp`, `iat`, or `nbf` values fail with `InvalidAccessToken`;
accepted credentials always retain their expiry metadata. Leeway uses checked
range validation and wide integer comparisons rather than overflowing addition.
