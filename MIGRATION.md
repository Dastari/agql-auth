# Migration Guide

## 0.18.0 to 0.19.0: opt-in super-scopes for exact-only requirements

Existing consumers need no configuration change. The compatibility default
keeps configured super-scopes from satisfying exact-only requirements, while
direct exact grants remain accepted and wildcard-derived matches remain
rejected.

A host that wants its configured super-scopes to apply to exact-only
requirements can enable the policy explicitly:

```rust
let matcher = HierarchicalScopeMatch::new(
    HierarchicalScopeOptions::default()
        .with_super_scopes(["root.admin", "operations.breakglass"])
        .with_allow_super_scopes_for_exact_only(true)
        .with_exact_only_scopes(["payments.credentials.release"]),
)?;
```

Only exact membership in `super_scopes` receives blanket authority. Wildcards,
hierarchical wildcard matches, related strings, and unrelated grants do not
satisfy an exact-only requirement. Disable the option to restore the previous
behavior. No token, database, role, or stored-scope migration is implied.

## 0.17.1 to 0.18.0: typed authorization roles and resilient catalogue policy

Existing issuers and validators need no configuration change. The new
`authorization_roles` claim defaults to an empty set and remains separate from
application `roles`.

An issuer adopting compact grants implements `AdditionalTokenRolesProvider`
and installs it with `AuthService::with_additional_token_roles_provider`. The
provider is called for login and every refreshable-session rotation. It is not
called for sessionless or session-bound delegated tokens. Resource servers
expand `AuthUser::token_claims.authorization_roles`, not application roles.

`StaticRoleScopeExpansion` now rejects unknown identifiers. Remote caches
should request an immediate refresh on that error, preserve their last
signature-verified snapshot when refresh fails, and fail the affected request
if the identifier remains unknown. Use
`RoleScopeCatalogueValidationOptions::default().with_*` to configure the
issuer's maximum signed lifetime and clock leeway independently of local
refresh frequency.

No database migration is implied. Membership storage, catalogue transport,
retry policy, and stale-while-revalidate bounds remain host-owned.

## 0.17.0 to 0.17.1: compact default session context

No API, database, or authorization migration is required. Newly serialized
`SessionContext` documents omit `mfa` when it is the default unsatisfied empty
state and omit `active_scope` when it is absent. Both fields already deserialize
with defaults, so typed consumers remain compatible. Consumers that compare raw
JWT JSON should accept the missing default-valued fields before updating the
issuer. Non-default MFA, assurance, and active-scope evidence remains explicit.

## 0.16.0 to 0.17.0: opt-in role-to-scope expansion

The release adds a provider-neutral expansion contract without changing token
issuance or validation defaults. Existing consumers need no changes.

Hosts adopting compact role grants should publish a bounded
`RoleScopeCatalogue`, verify its signature and binding outside `agql-auth`, and
construct `StaticRoleScopeExpansion` only from that verified snapshot. Union
the returned scopes with direct token scopes through `effective_scopes` before
authorization. A remote cache should implement `RoleScopeExpansionProvider`
and return `RoleScopeExpansionError::Unavailable` when it has no current,
verified snapshot. Unknown roles now fail explicitly so a consumer can refresh
and deny safely.

Roll out resource-server expansion before issuers stop placing expanded scopes
in tokens. Roll back by restoring expanded scope issuance while leaving the
additive provider contract unused. Membership persistence, catalogue URLs,
signing keys, and cache timing remain host-owned.

## 0.15.0 to 0.16.0: exact-only hierarchical requirements

`HierarchicalScopeOptions` adds `exact_only_scopes` and
`exact_only_scope_patterns`. Constructor and default users retain empty
compatibility defaults. The options type is now non-exhaustive: start from
`HierarchicalScopeOptions::default()` and use its `with_*` methods so future
fields do not break consumer construction. `HierarchicalScopeMatch::new` and
`ScopeMatcher::hierarchical` now return a validation `Result`.

To prevent blanket or wildcard grants from satisfying selected sensitive
requirements, provide the host-owned set:

```rust
let matcher = HierarchicalScopeMatch::new(
    HierarchicalScopeOptions::default()
        .with_super_scopes(["platform.admin"])
        .with_exact_only_scopes(["payments.credentials.release"]),
)?;
```

For a required scope in the set, matching stops at exact, case-sensitive grant
equality. All other requirements keep the configured hierarchical behavior.
The crate supplies no names or defaults, and no JWT, database, role, or stored
scope migration is required. Roll back by removing the configured values after
confirming that doing so is acceptable to the host's authorization policy.

Use `exact_only_scope_patterns` when the sensitive requirement contains a
resource identifier that cannot be enumerated. Pattern selection follows the
same configured wildcard grammar but never turns the pattern into a grant. A
bare-wildcard pattern is rejected. Other wildcard-bearing patterns produce a
validation warning that hosts should surface because each can select a whole
requirement subtree.

## 0.14.0 to 0.15.0: existing-session-bound delegation

Existing sessionless calls to `issue_access_token_only` remain valid and keep
their synthetic `sid` semantics. Newly issued sessionless tokens include the
closed `grant_kind = sessionless` claim. Normal refreshable access tokens use
`grant_kind = user_session`. Consumers that deserialize JWTs into exhaustive
wire structs must add the optional `grant_kind`, `session_version`, and
`operation` fields before upgrading issuers.

The session-bound contract is opt-in and requires no schema migration. To
adopt it:

1. Implement `VerifiedActiveUserSessionResolver` against the authoritative
   active-session store. Its read must reject revoked/expired records and load
   the exact subject, session/family/tenant, current session/security version,
   roles, scopes, assurance, and absolute/idle expiry without updating idle
   expiry or interactive last-active time.
2. Install the resolver during trusted startup with
   `with_active_user_session_resolver`.
3. Call `prepare_session_bound_access_token_only` with the initially resolved
   principal and a mandatory `SessionBoundDelegationBinding`, apply TTL or
   optional confirmation/custom claims to the returned opaque request, then
   call `issue_session_bound_access_token_only`. Preparation reads and stamps
   the authoritative version; issuance reads it again.
4. At every protected request, validate normal signature/issuer/audience plus
   the exact actor, resource, correlation, confirmation (when configured),
   operation binding, session version, and current session status. Reject
   delegated credentials from login/session-management endpoints with
   `authenticate_session_management_bearer` or
   `require_session_management_eligible`.

The issuer rechecks after initial resolution, but it cannot make application
store verification and JWT signing one transaction. The signed session version
is therefore mandatory: a revocation/version change after signing is rejected
by the next current-session assurance check.

`AuthConfig` adds `max_session_bound_delegation_ttl`; constructors default it
to 15 minutes. Exhaustive literals must initialize it to a positive value no
greater than `max_access_token_ttl`. `AccessTokenMetadata`,
`ClaimRequirements`, and `PrincipalReference` also have additive public fields.
No refresh-token, session-family, or delegated-session row is created, so no
database migration or backfill is required.

## 0.13.0 to 0.14.0: standard access-token `scope`

Version 0.14 changes newly issued access JWTs from the project-specific
`scopes` string array to the standard OAuth space-delimited `scope` string.
The in-process authorization model does not change: successfully validated
values still become `AuthUser::scopes: Vec<String>`, and guards and scope
matchers operate as before.

### Wire and source compatibility

Before 0.14, an access-token payload contained:

```json
{
  "scopes": ["users.read", "users.write"]
}
```

The 0.14 default is:

```json
{
  "scope": "users.read users.write"
}
```

An empty scope set omits `scope`. Purpose tokens are a separate token type and
continue using their purpose-specific `scopes` array. Opaque API/service
tokens, refresh tokens, stored sessions, and provider tokens are unchanged.

`AuthConfig` now has public `access_token_scope_claim_format` and
`legacy_scope_claims` fields. Constructor and builder users are
source-compatible. Exhaustive `AuthConfig` struct literals must add both
fields, normally as `AccessTokenScopeClaimFormat::Standard` and
`LegacyScopeClaims::Accept` during migration.

### Safe rolling deployment

Do not switch the issuer until every JWT consumer can read `scope`. A safe
order is:

1. Upgrade issuers and validators to 0.14 while temporarily keeping legacy
   issuance:

   ```rust
   use agql_auth::{
       AccessTokenScopeClaimFormat, AuthConfig, LegacyScopeClaims,
   };

   let config = AuthConfig::with_rs256_pem(private_pem, public_pem, key_id)
       .with_access_token_scope_claim_format(
           AccessTokenScopeClaimFormat::LegacyArray,
       )
       .with_legacy_scope_claims(LegacyScopeClaims::Accept);
   ```

2. Upgrade every router, resource server, worker, and other JWT consumer to
   accept the standard `scope` string. A 0.14 `AccessTokenValidator` accepts
   both representations by default.
3. Change issuers to `AccessTokenScopeClaimFormat::Standard`, or remove the
   temporary override to use the default. Keep legacy validation enabled.
4. Wait at least the maximum lifetime of every access token issued before the
   switch, including any configured validation clock skew. Refresh-token TTL
   is not the relevant window because refreshed sessions receive newly issued
   access tokens.
5. Reject legacy claims on the issuer's local validation path and every
   independent resource server:

   ```rust
   let config = config.with_legacy_scope_claims(LegacyScopeClaims::Reject);

   let validator = AccessTokenValidator::builder()
       // issuer, audience, and public-key configuration
       .legacy_scope_claims(LegacyScopeClaims::Reject)
       .build()?;
   ```

`AuthService::new` rejects the incoherent combination of legacy issuance and
legacy rejection. Issuance and validation are separate controls so a rolling
deployment can move forward without accepting new legacy tokens indefinitely.

### Validation behavior

In the default migration mode:

- `scope` alone is accepted;
- `scopes` alone is accepted;
- both claims are accepted only when they describe the same set, regardless
  of order or duplicates; and
- conflicting dual claims are rejected as an invalid access token.

`LegacyScopeClaims::Reject` rejects every token containing `scopes`, including
an empty array or an equivalent dual claim. Standard `scope` uses exactly one
ASCII space as its delimiter. Empty tokens, repeated delimiters, tabs,
newlines, non-ASCII values, quotes, backslashes, control characters, excessive
counts, and oversized values fail closed. The exported constants describe the
enforced count and byte limits.

### Rollback

If a consumer cannot read the standard claim, restore
`AccessTokenScopeClaimFormat::LegacyArray` on issuers and keep
`LegacyScopeClaims::Accept` on every validator. This affects only newly issued
access tokens; there is no storage migration to reverse. Existing standard
tokens continue to validate while legacy acceptance is enabled. Once the
consumer is fixed, repeat the staged switch and expiry window before enabling
strict rejection.

See [Access-token scope claims](docs/access-token-scope-claims.md) for the full
wire contract, security bounds, deployment inventory, and acceptance checks.

## 0.12.0 to 0.13.0: provider-neutral operation assurance

This change is additive and opt-in. Existing calls to
`RecentMfaPolicy::evaluate`, existing session/storage rows, ordinary refresh,
and `step_up_session` continue to behave as before. No database migration is
required.

### Before: route-local policy and message handling

```rust
policy.evaluate(&user, clock.as_ref())?;
// Each resource separately chose how to expose a denial.
```

### After: stable requirement and server-authored evaluation

```rust
let policy_id = AssurancePolicyId::new("interactive.recent-auth")?;
let requirement = AssuranceRequirement::new(policy_id.clone());

let mut policies = AssurancePolicySet::new();
policies.insert(policy_id, policy);

let evaluation = policies.evaluate(&requirement, user.as_ref(), clock.as_ref());
if let Some(code) = evaluation.state.graphql_extension_code() {
    return Err(graphql_error_with_code(code));
}
```

The server evaluation time comes from one read of the injected clock. A
satisfied result carries typed `AuthenticatedAt` and inclusive
`SatisfiedUntil` values. Unknown policy IDs fail closed as `FORBIDDEN`; absent
users are `UNAUTHENTICATED`; assurance failures are `STEP_UP_REQUIRED` with a
detailed `AssuranceDenialCode`.

### Staged adoption

1. Define stable policy IDs and populate an `AssurancePolicySet` beside the
   existing `RecentMfaPolicy` configuration.
2. Expose `SessionAssuranceStatus` only if clients need advisory step-up UX.
   Do not expose `AuthPayload`, token claims, raw provider responses, or stored
   refresh records as status.
3. Convert one protected resource at a time to `AssuranceRequirement` and
   `AssuranceEvaluation`. Keep server-side evaluation immediately before the
   protected work.
4. Map `AssuranceEvaluationState::graphql_extension_code()` into the transport
   error. Retain detailed denial codes for bounded telemetry; stop matching
   human-readable messages.
5. After every protected resource is classified, enable any host-level
   completeness gate. Client manifests remain advisory.

Hosts may continue using provider-neutral evidence including password plus
TOTP, verified OIDC reauthentication, WebAuthn, or a host-defined method and
context. The host still verifies all external evidence before calling
`step_up_session`. Ordinary refresh is never a substitute: it rotates
credentials but preserves the original authentication time and satisfaction
deadline.

### Compatibility and rollback

The new public types do not change default enforcement, serialized session
shape, refresh-store traits, or token claims. Legacy sessions without assurance
still refresh and fail only at an opted-in assurance policy. To roll back,
remove requirement evaluation from the affected resources and restore their
prior direct `RecentMfaPolicy::evaluate` calls; stored sessions and refresh
tokens need no rewrite. During rollback, remove any client expectation that an
advisory status or manifest authorizes execution.

## 0.11.0 to 0.12.0: bound list-valued `acrs` step-up

Use the new typed request only when the host has an exact provider context to
request and a separate local allowlist/mapping for the returned evidence:

```rust
let options = OidcAuthorizationOptions {
    prompt: vec![OidcPrompt::Login],
    max_age: Some(300),
    acr_values: Vec::new(),
    id_token_claims: vec![
        OidcIdTokenClaimRequest::EssentialAuthTime,
        OidcIdTokenClaimRequest::EssentialAcrs {
            value: "c1".to_string(),
        },
    ],
};
let expected = options.validate()?;
```

This produces one standard OIDC `claims` parameter whose ID-token member asks
for essential `auth_time` and essential list-valued `acrs` using the singular
exact `value` form. The callback independently enforces fresh `auth_time` and
requires the validated `acrs` list to contain `c1`. The exact match is returned
as `OidcAuthorizationOutcome.matched_acrs`; the host must still call
`require_bound_policy`, allowlist/map the context, and apply its own endpoint
authorization and current-session rules.

Policies that request `acrs` use stored representation version 2. Existing
version 1 policies remain valid only without the new field, so in-flight 0.11
requests keep their behavior. Legacy/default callbacks and mismatched policies
cannot satisfy a route expecting the version 2 policy. No OAuth state store
trait or schema change is required when the policy is already stored as the
document/JSON representation. Typed relational representations must add the
optional exact `essential_acrs_value` and retain the version.

`OidcIdTokenClaimRequest` has a new enum variant and
`OidcAuthorizationOutcome` has a new public field. Update exhaustive matches
and outcome struct literals. Do not replace this request with `acr_values` or
standard `EssentialAcr`: those represent standard scalar `acr`, not provider
list-valued `acrs`.

Tests prove serialization, binding, validation, and redaction boundaries only.
Live provider challenge behavior, returned evidence, local mapping, endpoint
approval, activation, and revocation remain deployment gates.

## 0.10.0 to 0.11.0: atomic durable rate-limit attempts

Version 0.11 replaces the split rate-limit read/save contract with versioned
compare-and-swap. This prevents concurrent service instances from reading
attempt count `n` and both replacing it with `n + 1`.

### Store API migration

`find_auth_rate_limit_state` now returns
`Option<AuthRateLimitSnapshot>`. Replace `save_auth_rate_limit_state` with
`compare_exchange_auth_rate_limit_state`, and make clear conditional:

```rust
async fn compare_exchange_auth_rate_limit_state(
    &self,
    key: &AuthRateLimitKey,
    expected_revision: Option<Uuid>,
    replacement: AuthRateLimitSnapshot,
) -> AuthResult<bool>;

async fn clear_auth_rate_limit_state(
    &self,
    key: &AuthRateLimitKey,
    expected_revision: Option<Uuid>,
) -> AuthResult<bool>;
```

With no expected revision, compare-exchange succeeds only for an absent key.
With a revision, it succeeds only for an exact match. Conflict returns
`Ok(false)` without mutation. Conditional clear follows the same rule. The
service generates a fresh UUID for every replacement, recomputes the state
transition after conflict, and never falls back to split replacement.

`AuthRateLimitState` itself is unchanged. Durable stores need a UUID revision
column or equivalent value stored atomically beside it. Backfill every existing
row with a distinct revision before deploying the 0.11 writer. JSON/document
stores may wrap the existing state as:

```json
{
  "state": { "existing": "AuthRateLimitState fields" },
  "revision": "one unique UUID per committed version"
}
```

For SQLite, use a write transaction or conditional insert/update that tests the
stored revision; the unique full key resolves first-insert races. For
PostgreSQL, use `SELECT ... FOR UPDATE`, a conditional update, or an upsert
whose update predicate matches the expected revision. Clear must delete only
the matching revision. Do not implement compare-exchange as a read followed by
an unconditional upsert.

### Service and clock behavior

Existing `AuthService::new` and `new_with_rate_limit_store` remain available
and use `SystemClock`. Deterministic tests can use:

```rust
let auth = AuthService::new_with_rate_limit_store_and_clock(
    config,
    user_store,
    refresh_store,
    rate_limit_store,
    Arc::new(FixedClock::new(now)),
)?;
```

Password-reset and login-code request admission is now linearized with its
per-key attempt write. The attempt that first activates backoff remains allowed,
matching 0.10 behavior; later concurrent requests are denied. Credential
failures always record through CAS, including failures that began before a
concurrent attempt activated lockout.

A successful credential flow receives an internal observation permit before
verification and clears only unchanged revisions afterward. If a newer failure
commits meanwhile, conditional clear returns a conflict and the newer failure
remains. Expired-state cleanup is no longer an unconditional service delete;
the next attempt resets it through CAS, and stores may delete expired rows with
their normal conditional/background cleanup.

Atomicity is per full `AuthRateLimitKey`. Principal and client buckets are
evaluated independently and are not committed as one cross-key transaction.
Store failures retain the existing safe `AUTH_SERVICE_UNAVAILABLE` public
category; backend details remain available only through internal errors.

Memory-store-only consumers need no data migration, but custom trait
implementations must update before compiling. See
[atomic abuse protection](docs/abuse-protection.md) for backend and conformance
guidance.

## 0.9.0 to 0.10.0: bound OIDC reauthentication

Existing calls to `create_authorization_request` retain their standard PKCE,
nonce, state, scope, redirect, response-type, and response-mode behavior. They
create no bound policy. Use `create_authorization_request_with_options` only for
flows that need provider-enforced recent authentication or exact standard ACR
evidence.

```rust
use agql_auth::{
    OidcAuthorizationOptions, OidcIdTokenClaimRequest, OidcPrompt,
};

let options = OidcAuthorizationOptions {
    prompt: vec![OidcPrompt::Login],
    max_age: Some(300),
    acr_values: Vec::new(),
    id_token_claims: vec![OidcIdTokenClaimRequest::EssentialAuthTime],
};
let expected = options.validate()?;
let request = provider
    .create_authorization_request_with_options(&oauth_state_store, options)
    .await?;

// At the dedicated reauthentication callback endpoint:
let outcome = provider
    .handle_callback(&oauth_state_store, callback_input)
    .await?;
outcome.authorization.require_bound_policy(&expected)?;
```

`max_age` and essential `auth_time` cause callback validation to require a
numeric signed `auth_time`. Exact max age plus configured clock skew is allowed;
one second older is denied. Future skew uses the same inclusive rule. Use
`OidcProvider::new_with_clock` for deterministic host tests.

### OAuth state storage

`OAuthLoginState` adds
`authorization_policy: Option<OidcAuthorizationPolicy>`. The
`OAuthStateStore` trait methods are unchanged. JSON/document records missing the
field deserialize as `None`; a legacy in-flight login remains a normal login and
must not be accepted by an endpoint that calls `require_bound_policy`.

Relational stores should deploy a nullable JSON/typed column reader before
enabling typed request writers:

```sql
ALTER TABLE oauth_states
    ADD COLUMN authorization_policy JSON NULL;
```

Atomic consume queries must return the optional policy with the same
pre-consumption state snapshot. Implementations constructing public records
must add `authorization_policy: None`. Unknown/corrupt versions fail closed.

### Public struct and error changes

- `OidcAuthorizationRequest.authorization_policy`
- `OAuthLoginState.authorization_policy`
- `ValidatedOidcClaims.acrs`
- `OidcLoginResult.authorization`
- `AuthError::InvalidOidcAuthorizationOptions`

These additions can require changes to exhaustive matches and struct literals,
which is why this is `0.10.0` rather than a patch release.

Do not map `prompt=login`, `max_age`, `auth_time`, provider kind, standard
scalar `acr`, or provider `acrs` to MFA implicitly. Entra `acrs` ID-token
behavior requires a separately configured and proven provider contract. See
[bound OIDC reauthentication](docs/oidc-step-up.md) for the full trust boundary,
provider limitations, and long-lived-operation guidance.

## 0.8.1 to 0.9.0: durable principal lifecycle primitives

No existing call-site, database, token, session, or serialized-record migration
is required. Version 0.9.0 adds opt-in APIs for disconnected or long-lived work.

Persist `AuthPrincipal::reference()` instead of a bearer token or a cloned
roles/scopes snapshot. Implement `CurrentPrincipalResolver` in the host using
its authoritative session/token and membership stores. Before every protected
operation, resolve the reference and use only the roles, scopes, assurance, and
status on the returned `ResolvedPrincipal`.

`PrincipalReference` and `PurposeBoundGrantReference` are identifiers and
bindings, not authorization proofs. Resolver authorization remains mandatory,
and implementations must fail closed when current authority cannot be loaded.

`AuthorizationDecision` is structurally unchanged. Calling
`with_invocation(...)` now produces a `LinkedAuthorizationDecision` wrapper so
hosts can correlate authorization and application audits without changing the
actor or granting authority.

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

let matcher = Arc::new(HierarchicalScopeMatch::new(
    HierarchicalScopeOptions::default().with_super_scopes(["platform.admin"]),
)?);

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
