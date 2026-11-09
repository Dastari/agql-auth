# Multi-Tenant And Sender-Binding Claims

`agql-auth` provides project-agnostic typed support for optional access-token
claims. No tenant ID format, device certificate format, or product vocabulary is
hard-coded.

## Optional Claims

| Claim / field | Purpose |
|---------------|---------|
| `jti` | Unique token id for revocation and audit |
| `tenant_id` | Tenant / organization boundary |
| `organization_id` | Distinct org when needed |
| `session_family_id` | Family-wide session revocation |
| `actor` | On-behalf-of / impersonation identity |
| `auth_time` | Authentication time |
| `amr` | Authentication method references |
| `acr` | Authentication context class |
| `cnf` | Confirmation binding (`x5t#S256` and/or `jkt`) |
| `resource_type` / `resource_id` | Resource binding |
| `correlation_id` | Audit correlation |

These map into `AccessTokenMetadata` on `AuthUser.token_claims`.

## Compatibility Strategy

1. All fields are optional on decode.
2. Existing tokens without these claims continue to validate under default policy.
3. Resource servers opt into requirements explicitly.
4. A future major release may tighten defaults after a documented migration window.

## Claim Requirements

```rust
use agql_auth::{AccessTokenValidator, ClaimRequirements};

let validator = AccessTokenValidator::builder()
    .issuer("agql-auth")
    .audience("orders-api")
    .rs256_public_pem(public_pem)
    .claim_requirements(ClaimRequirements::tenant_and_jti())
    .build()?;
```

Profiles:

- `ClaimRequirements::none()` — compatibility default
- `ClaimRequirements::tenant_and_jti()` — multi-tenant API baseline
- `ClaimRequirements::tenant_jti_and_cnf()` — multi-tenant + verified
  proof-of-possession

## Confirmation (`cnf`) Binding

`require_cnf` checks possession, not just that a `cnf` claim exists. The host
verifies the client certificate (mTLS, RFC 8705) or the DPoP proof key
(RFC 9449) itself and passes the resulting SHA-256 thumbprint; the validator
compares it with `cnf` in constant time:

```rust
use agql_auth::{AccessTokenValidator, ClaimRequirements, PresentedConfirmation};

let validator = AccessTokenValidator::builder()
    .issuer("agql-auth")
    .audience("orders-api")
    .rs256_public_pem(public_pem)
    .claim_requirements(ClaimRequirements::tenant_jti_and_cnf())
    .build()?;

// Thumbprint of the certificate the TLS layer authenticated for this request.
let presented = PresentedConfirmation::certificate_thumbprint(cert_x5t_s256);
let user = validator.authenticate_bearer_with_confirmation(authorization_header, &presented)?;
```

With `require_cnf` set, the plain `authenticate_access_token`,
`authenticate_bearer`, `inject_http_auth` and `authenticate_connection_init_value`
paths fail closed, because they have no presented key to compare. Use the
`*_with_confirmation` methods (`inject_http_auth_with_confirmation` for request
injection). Every confirmation method in the token must match:
a token bound with both `x5t#S256` and `jkt` needs both thumbprints. When the
caller presents material, a token carrying `cnf` is always checked, even without
`require_cnf`. Hosts that read `AccessTokenMetadata::cnf` themselves can call
`AccessTokenMetadata::verify_confirmation`.

## Delegated And Actor Tokens

`AccessTokenMetadata::is_delegated()` is true for a session-bound delegation
(`grant_kind = session_bound_delegation`) and for any token carrying `actor`.
The crate's user and principal guards refuse such tokens unless the guard opts
in with `allow_delegated()`; see [Authorization](authorization.md#delegated-tokens).

## Issuing Claims

Access-token-only grants accept typed optional fields:

```rust
use agql_auth::{AccessTokenOnlyRequest, AuthMethod, SessionContext};
use time::Duration;

let grant = auth
    .issue_access_token_only(
        AccessTokenOnlyRequest::new(
            "user-1",
            vec!["Operator".into()],
            vec!["orders.read".into()],
            SessionContext::for_auth_method(AuthMethod::ServiceToken),
        )
        .with_tenant_id("tenant-1")
        .with_ttl(Duration::minutes(15)),
    )
    .await?;
```

Normal session issuance always includes a unique `jti` and may carry
`session_family_id` for refresh-family correlation.

## Bridge Notes For `graphql-orm`

Expose at least:

- subject / user id
- tenant id from `AuthUser.token_claims.tenant_id` or session active scope
- roles and scopes
- `AccessTokenMetadata`
- token/session reference (`jti` or session id)
- request `ScopeMatch` / `AuthRuntime`

`agql-auth` does not depend on `graphql-orm`.
