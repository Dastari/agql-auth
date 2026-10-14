# Durable Principal Lifecycle

Long-lived jobs, subscriptions, and internal request bridges must not persist a
bearer credential or treat roles and scopes captured at creation time as
current authority. `agql-auth` provides project-agnostic references and
rehydration contracts for that boundary.

## Persist a Non-Secret Reference

```rust
use agql_auth::AuthPrincipal;

let reference = principal.reference();
persist_for_later(&reference).await?;
```

`PrincipalReference` contains stable identity, session/token, session version,
grant kind, audience, tenant, actor, resource, exact operation, expiry, and
correlation references where available. It deliberately omits bearer values,
token hashes, cookies, roles, and scopes. It is not proof that the principal
remains active or authorized.

## Rehydrate Current Authority

Hosts implement `CurrentPrincipalResolver` against their authoritative stores:

```rust
use agql_auth::{
    AuthResult, CurrentPrincipalResolver, PrincipalReference, ResolvedPrincipal,
};
use async_trait::async_trait;
use time::OffsetDateTime;

struct HostPrincipalResolver;

#[async_trait]
impl CurrentPrincipalResolver for HostPrincipalResolver {
    async fn resolve(
        &self,
        reference: &PrincipalReference,
    ) -> AuthResult<ResolvedPrincipal> {
        let principal = load_and_validate_current_principal(reference).await?;
        ResolvedPrincipal::new(reference.clone(), principal, OffsetDateTime::now_utc())
    }
}
```

The host must check current session/token status, revocation, expiry,
membership, assurance, roles, and scopes. `ResolvedPrincipal::new` additionally
verifies that immutable identity and resource bindings match the requested
reference. Callers then use only `resolved.principal()` for current authority.

For `session_bound_delegation`, actor/resource/operation values belong to the
delegated token while the resolved principal represents the underlying normal
user session. `ResolvedPrincipal::new` therefore requires exact subject,
session, family, tenant, and session version continuity while retaining the
delegation bindings on the reference for the protected operation to enforce.

Rehydrate before every protected operation, after approval, before external
disclosure, and before each sensitive subscription event or job action. Periodic checks
are an additional connection-lifetime measure, not immediate revocation.

`VerifiedActiveUserSessionResolver` is the stricter read-only adapter used by
session-bound token issuance. It must not touch idle expiry or interactive
last-active timestamps. See [Access-token-only grants](access-token-only.md).

## Purpose-Bound Grants

`PurposeBoundGrantReference` describes an exact subject, audience, resource,
action, purpose, validity interval, and revocation state. Its `evaluate` method
checks that exact boundary against a current principal. An active result still
does not replace ordinary application authorization.

## Linked Authorization Audits

`AuthorizationDecision::with_invocation` produces a
`LinkedAuthorizationDecision`. The wrapper adds a safe mechanism, causation ID,
and optional grant reference while retaining the original actor and decision.
Never put credentials, prompts, request bodies, or protected arguments in this
metadata.

## Current authority for sensitive operations

See [the 0.20 migration](../MIGRATION.md#0192-to-0200-current-authority-and-sensitive-operations)
for mandatory immediate status/current-grant checks and refresh provenance.
Refresh narrows the previous role/scope ceiling. Password sessions use current
StoredUser grants; custom/OIDC sessions require `RefreshGrantAuthority`.
Legacy refresh records require reauthentication. Persist `grant_source` and
`roles` alongside scopes in the same atomic rotation.

For each sensitive operation or subscription event, use
`revalidate_sensitive_principal` with an authoritative `TokenStatusChecker`
and `CurrentPrincipalResolver`, then use the returned narrowed principal for
policy/context injection. Keep the original credential bindings available for
resource/operation/tenant/audience/purpose/confirmation enforcement. Signature
validation, periodic checks and always-active checkers do not establish immediate
revocation. Missing authority or status must deny. A decision observes state at
evaluation; subsequent writes need host transaction/version fencing where atomic
revocation ordering is required.

For session-bound delegation, the resolver returns the current parent session;
the requested delegation reference must remain exact and its subject/session,
family, tenant, session version and active business scope must match that parent.
The status checker independently checks the original delegated token, even when
the parent is active. All original delegation bindings remain on the narrowed
result and must be enforced by the operation policy.

The [compilable boundary example](../examples/current-authority.rs) shows calling
the helper before a sensitive scope decision.
