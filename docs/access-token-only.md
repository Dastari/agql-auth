# Access-Token-Only Grants

Use `AuthService::issue_access_token_only` when the host needs a short-lived
user-shaped access JWT without creating a refresh token or refresh-store row.

## When To Use

- Machine / workload credentials that should look like access JWTs
- Device-bound short grants after host verification
- One-shot operator actions
- Downstream service calls where refresh is handled elsewhere

Do not use this path for interactive browser sessions that need refresh
rotation.

## API

```rust
use agql_auth::{AccessTokenOnlyRequest, AuthMethod, SessionContext};
use time::Duration;

let grant = auth
    .issue_access_token_only(
        AccessTokenOnlyRequest::new(
            "device-user-1",
            vec!["Device".into()],
            vec!["devices.read".into()],
            SessionContext::for_auth_method(AuthMethod::ServiceToken),
        )
        .with_ttl(Duration::minutes(30))
        .with_tenant_id("tenant-1"),
    )
    .await?;

// grant.access_token  — raw JWT (redacted in Debug)
// grant.access_token_expires_at
// grant.user          — AuthUser including jti / metadata
```

## Guarantees

- No refresh token is generated
- No refresh-token store insert occurs
- `purpose` is `access_token`
- `typ` is `access`
- A unique `jti` is included
- TTL must be positive and `<= AuthConfig::max_access_token_ttl` (default 24h)
- Roles and scopes are deterministically deduplicated
- Scopes use the same standard OAuth `scope` claim and migration policy as
  session access tokens

## Validation

Issued tokens validate through both `AuthService` and `AccessTokenValidator`
using the shared decode core.

See [Access-token scope claims](access-token-scope-claims.md) for legacy-array
compatibility, strict validation, and rollout guidance.
