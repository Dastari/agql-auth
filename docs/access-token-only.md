# Access-Token-Only Grants

`agql-auth` has two intentionally separate access-token-only contracts. Both
produce user-shaped JWTs and neither creates a refresh token or store row, but
only one is allowed to retain an existing user session ID.

- `issue_access_token_only` is sessionless. It retains the existing service,
  device, and one-shot behavior and creates a synthetic JWT `sid` that is not
  an active login session.
- `issue_session_bound_access_token_only` is a tightly bound delegation from
  an existing active user session. It re-reads that session inside the service,
  preserves its exact subject and `sid`, and is appropriate for short-lived
  registered application-tool execution.

## When To Use

- Machine / workload credentials that should look like access JWTs
- Device-bound short grants after host verification
- One-shot operator actions
- Downstream service calls where refresh is handled elsewhere

Do not use either path to create an interactive browser session.

## Sessionless API

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
- `grant_kind` is `sessionless`

The synthetic `sid` deliberately does not resolve as an active user session.
Do not use this contract for resolvers that perform current-session assurance.

## Existing-Session-Bound Delegation

Configure one trusted read-only `VerifiedActiveUserSessionResolver` during
application startup. The resolver must load the authoritative active-session
record without updating idle expiry or interactive last-active time, reject a
revoked or expired session, load current roles/scopes/assurance/tenant, and
return its current session/security version and absolute/idle expiry:

```rust
let auth = AuthService::new(config, users, refresh_tokens)?
    .with_active_user_session_resolver(active_sessions);
```

Construct one request with mandatory actor, resource, correlation, and exact
registered operation bindings. The source principal may come from a legacy JWT
without `session_version`; preparation obtains the current version from the
authoritative resolver:

```rust
use agql_auth::{
    ActorIdentity, ExactOperationBinding, SessionBoundDelegationBinding,
};
use time::Duration;

let binding = SessionBoundDelegationBinding::new(
    ActorIdentity {
        sub: "fame-ai".into(),
        amr: vec!["service".into()],
    },
    "graphql_operation",
    registered_operation_id,
    correlation_id,
    ExactOperationBinding::new(operation_name, document_sha256),
);
let request = auth
    .prepare_session_bound_access_token_only(
        &initially_resolved_principal,
        narrowed_roles,
        narrowed_scopes,
        binding,
    )
    .await?
    .with_ttl(Duration::minutes(5));

let grant = auth
    .issue_session_bound_access_token_only(request)
    .await?;
```

The initial `ResolvedPrincipal` supplies only a non-secret reference. It is not
issuance proof. Preparation performs an authoritative read and stamps the
opaque request with the current session version; this also supports legacy
source JWTs that did not contain a version. Immediately before signing,
`AuthService` calls its configured resolver again and checks the exact
subject/session/family/tenant/version, current status, current roles, current
scopes, and current assurance. A change between preparation and this second
read fails closed. Every protected use must perform its normal current-session/
status check, so a later logout, revocation, expiry, assurance-version change,
or permission change takes effect on the next request.

Roles use exact membership. Scope narrowing uses the `AuthService`'s trusted
`ScopeMatch` configured at startup: exact matching by default, or the same
host-selected wildcard/super-scope semantics used for authorization. No
caller-supplied boolean or string-prefix proof is accepted.

The delegated token:

- preserves authoritative subject, `sid`, session family, tenant/organization,
  assurance context, authentication time, AMR/ACR, and session version;
- has `grant_kind = session_bound_delegation` and a unique `jti`;
- contains only the requested authority proven to be a subset of current
  authority;
- expires at the earliest of requested TTL, configured
  `max_session_bound_delegation_ttl`, and remaining absolute/idle session
  lifetime;
- requires signed actor, resource, correlation, and exact-operation bindings;
- refuses to replace an actor, confirmation, or resource binding already
  present on the authoritative session (hosts need an explicit richer actor
  chain contract before delegating such a session);
- creates no refresh token, delegated session, session family, or login row;
- cannot be used as the source of another delegation; and
- must be rejected by session-management handlers using
  `authenticate_session_management_bearer` (or, for an already decoded user,
  `AuthUser::require_session_management_eligible`).

Resource servers still validate the normal issuer/audience/signature and must
enforce the exact actor, resource, correlation, confirmation (when used), and
operation binding at the protected resolver or middleware boundary. Retaining
the real `sid` is what allows that boundary to apply ordinary resolver-side
revocation and assurance checks; it does not turn the delegated token into a
general browser credential.

The final signing interval cannot be one transaction with an application-owned
session store. The signed session version closes that boundary at the next
status check: hosts must compare it to the authoritative record and fail closed
when it changes.

## Validation

Issued tokens validate through both `AuthService` and `AccessTokenValidator`
using the shared decode core. Use `ClaimRequirements` to require delegation
kind, session version, actor/resource/correlation, confirmation, and operation
claims at resource-server boundaries.

See [Access-token scope claims](access-token-scope-claims.md) for legacy-array
compatibility, strict validation, and rollout guidance.
