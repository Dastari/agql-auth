# Changelog

## 0.13.0

### Added

- Provider-neutral `AssurancePolicyId` / `AssuranceRequirement` declarations,
  `AssurancePolicySet`, and server-authored `AssuranceEvaluation` results with
  typed evaluation, authentication, and inclusive satisfaction timestamps.
- Stable evaluation states for satisfied, step-up-required, unauthenticated,
  and forbidden decisions. Detailed `AssuranceDenialCode` values map directly
  to `STEP_UP_REQUIRED`, `UNAUTHENTICATED`, or `FORBIDDEN` GraphQL categories
  without parsing messages.
- `SessionAssuranceStatus`, a credential-free client projection that exposes
  only validated authentication time and MFA satisfaction.

### Security

- Unknown policies fail closed, clocks are read exactly once per evaluation,
  and all time arithmetic remains checked.
- Safe status serialization omits session IDs, token claims, ACR/context
  values, raw credentials, secrets, and provider payloads.
- Ordinary refresh continues rotating credentials without changing
  `authenticated_at` or extending recent-authentication eligibility. Only a
  host-verified `step_up_session` call changes session assurance.

### Compatibility / SemVer

- Existing `RecentMfaPolicy::evaluate`, `SessionAssurance`, refresh, and step-up
  APIs remain source-compatible. The policy-ID/evaluation/status APIs are
  additive and opt-in; no storage migration or default enforcement change is
  required.

## 0.12.0

### Added

- `OidcIdTokenClaimRequest::EssentialAcrs { value }`, a bounded typed request
  for one exact provider list-valued `acrs` authentication-context reference.
- Deterministic OIDC `claims` serialization using the singular exact `value`
  form, alongside typed `auth_time` and standard scalar `acr` requirements.
- `OidcAuthorizationOutcome.matched_acrs`, which exposes only the exact context
  matched for the bound callback and remains distinct from scalar `acr`, AMR,
  and local MFA acceptance.

### Security

- Policies containing an `acrs` requirement use stored representation version
  2. Version 1 remains canonical for requests without `acrs`; a version 1
  record containing the new requirement, a version 2 record missing it, and
  unknown versions fail closed before token exchange.
- After ordinary ID-token validation, a bound `acrs` request requires a typed,
  bounded list containing the exact case-sensitive requested value. Missing,
  malformed, blank, duplicate, wrong, excessive, per-value oversized, and
  aggregate-oversized evidence is denied.
- Provider/JWT decoding failures now use bounded coarse diagnostics so malformed
  context values and provider responses cannot be echoed through errors. Debug
  output reports only the presence/count of `acrs` requirements and matches.
- Matching `acrs` remains provider evidence only and does not bypass independent
  essential/fresh `auth_time`, host allowlisting, assurance mapping, or local
  authorization.

### Compatibility / SemVer

- Existing requests without `EssentialAcrs` retain policy version 1 and their
  authorization URL and callback behavior. Legacy state remains readable and
  cannot satisfy `require_bound_policy` for a version 2 request.
- The new public enum variant and `OidcAuthorizationOutcome` field can require
  updates to exhaustive matches and struct literals. These additive public API
  and stored-policy changes make `0.12.0` a pre-1.0 minor release.
- Distribution remains Git-only. Unit and boundary tests do not establish live
  Microsoft Entra or host-deployment acceptance.

## 0.11.0

### Added

- `AuthRateLimitSnapshot`, which pairs persisted abuse state with a fresh,
  opaque UUID revision for portable compare-and-swap.
- Required object-safe `AuthRateLimitStore` compare-exchange and conditional
  clear operations. The service retains all window, reset, backoff, lockout,
  expiry, and retry calculations and retries compare conflicts.
- `AuthService::new_with_rate_limit_store_and_clock` for deterministic
  rate-limit window, expiry, backoff, lockout, and retry-after decisions.
- Barrier-start, two-service concurrency coverage for first inserts, existing
  state, request admission, credential failures, reset boundaries, maximum
  values, and record-versus-clear races.

### Changed

- Request initiation admission and attempt recording now share one linearized
  per-key compare-and-swap decision. The first request that activates backoff
  remains admitted; concurrent later requests observe the committed backoff.
- Successful credential flows clear only the exact revisions observed before
  verification. A concurrent newer failure is retained.
- Expired state is ignored during checks and reset by the next successful CAS;
  stores may continue deleting it as background maintenance.
- Attempt and timestamp arithmetic is overflow-safe. Attempt counts cap at
  `u32::MAX`; unsafe time arithmetic returns a safe configuration error rather
  than wrapping or panicking.
- `AuthRateLimitKey` Debug output redacts its opaque `value_hash`.

### Compatibility / SemVer

- `AuthRateLimitStore` implementors must migrate from split `find/save/clear`
  operations to versioned find, compare-exchange, and conditional clear. No
  unsafe default fallback is provided.
- Durable stores need a non-reusable UUID revision per key/version. Existing
  rows require a one-time unique revision backfill. `AuthRateLimitState` fields
  and public throttled/locked errors are otherwise unchanged.
- Existing `AuthService` constructors remain available and use `SystemClock`;
  the in-memory store implements the same atomic contract.
- Atomicity is per `AuthRateLimitKey`; principal and client buckets are not one
  cross-key transaction.
- These public trait and persisted-record changes make `0.11.0` a pre-1.0
  minor release. Distribution remains Git-only.

## 0.10.0

### Added

- `OidcAuthorizationOptions`, typed `OidcPrompt` values, bounded `max_age` and
  `acr_values`, and typed essential ID-token `auth_time`/standard `acr` claim
  requests.
- `OidcProvider::create_authorization_request_with_options`, which normalizes
  options before state insertion and binds a versioned
  `OidcAuthorizationPolicy` to the exact one-time OAuth state.
- Callback enforcement for mandatory/fresh `auth_time` and exact standard
  scalar `acr`, with inclusive checked clock-skew boundaries and
  `OidcProvider::new_with_clock` for deterministic tests.
- `OidcAuthorizationOutcome` and `require_bound_policy`, allowing a host
  endpoint to reject a normal-login callback where a specific bound
  reauthentication policy is required.
- Strictly typed, bounded provider `acrs` list exposure on
  `ValidatedOidcClaims`, kept separate from standard scalar `acr`.

### Security

- Authorization options have no arbitrary query-parameter map. Invalid prompt
  combinations, negative/over-limit ages, duplicate/blank/control/oversized
  values, conflicting ACR requests, malformed claims, and stored-policy
  corruption fail closed.
- `max_age` always requires signed `auth_time`; future, stale, negative,
  malformed, and arithmetically unsafe timestamps are denied after ordinary ID
  token and one-time state validation.
- Provider `auth_time`, `amr`, `acr`, and `acrs` remain evidence only. Active
  reauthentication never becomes local MFA without explicit host acceptance.
- Debug output now redacts complete authorization URLs, OAuth state, nonce,
  PKCE values, raw validated claims, and external-identity claim snapshots.
  Provider callback/token error text is not echoed into displayed errors.

### Compatibility / SemVer

- `OAuthLoginState` adds optional `authorization_policy`; missing legacy state
  deserializes as `None` and means no requested step-up. `OAuthStateStore`
  signatures are unchanged, but relational schemas and struct literals need an
  optional field.
- `OidcAuthorizationRequest`, `ValidatedOidcClaims`, and `OidcLoginResult` gain
  public fields. `AuthError` gains `InvalidOidcAuthorizationOptions`. These
  structural public changes make `0.10.0` a pre-1.0 minor release.
- Microsoft Entra `acrs` issuance in an ID token is not assumed. Hosts need a
  separately configured and proven tenant/application/token-type contract and
  an exact local allowlist.
- This remains a Git-only distribution and is not published to crates.io.

## 0.9.0

### Added

- `PrincipalReference` and `PrincipalReferenceKind` for persisting stable,
  non-secret identity and resource bindings without bearer credentials or
  stale role/scope snapshots.
- `CurrentPrincipalResolver` and `ResolvedPrincipal` for host-authoritative
  current-principal rehydration with immutable identity validation.
- `PurposeBoundGrantReference` and `PurposeGrantStatus` for exact,
  expiring, revocable audience/resource/action/purpose grant evaluation.
- `AuthorizationInvocation` and `LinkedAuthorizationDecision` for linking
  ordinary authorization audits to an internal or transport invocation without
  replacing the authenticated actor.

### Security

- Principal references deliberately omit roles, scopes, bearer values, token
  hashes, cookies, and authorization headers. Long-lived work must rehydrate
  current authority and fail closed on status or storage errors.
- Resolved principals must retain the referenced identity, session/token,
  tenant, audience, actor, and resource bindings. A reference or purpose-bound
  grant is not authorization and cannot add authority.

### Compatibility

- Existing authentication, token, guard, store, and authorization-decision APIs
  are unchanged. Invocation metadata uses an additive wrapper rather than a new
  field on `AuthorizationDecision`, preserving struct-literal compatibility.
- No database or serialized-record migration is required. Hosts opt in by
  persisting `PrincipalReference` values and implementing
  `CurrentPrincipalResolver`.
- This remains a Git-only distribution and is not published to crates.io.

## 0.8.1

### Fixed

- Locally issued access tokens now omit unset optional top-level claims instead
  of serializing them as JSON `null`. In particular, an unset registered `nbf`
  claim is absent, preserving its RFC 7519 NumericDate type when present and
  interoperability with strict JWT resource servers.
- The same omission rule is applied consistently to optional access-token
  metadata and reviewed across the private password-reset and purpose-token
  claim representations.

### Compatibility

- Deserialization remains backward compatible: omitted optional claims decode
  as `None`, and numeric `nbf` validation, clock injection, leeway, signatures,
  issuer, and audience policy are unchanged.
- No public API or storage trait changed. Hosts do not need to set `nbf` when
  no not-before constraint is intended; omission is the correct representation.
- This remains a Git-only distribution and is not published to crates.io.

## 0.8.0

### Added

- `SessionAssurance`, `MfaAcceptance`, and normalized AMR/ACR/context bounds for
  host-authoritative authentication facts.
- `AuthService::issue_assured_user_session` and
  `issue_session_for_user_with_metadata` for refreshable sessions with assurance
  and explicitly refresh-safe standard metadata.
- `RefreshableTokenMetadata`, limited to tenant, organization, actor, and
  correlation metadata.
- `AuthService::step_up_session`, which rotates only the selected session and
  records the genuine step-up time from an injected `Clock`.
- `RecentMfaPolicy` with injected-clock max-age/skew checks, configurable AMR/ACR
  AND/OR matching, stable public denial codes, and separate internal detail.
- Typed OIDC `auth_time`, normalized `amr`, and `acr` on
  `ValidatedOidcClaims`, with strict type, size, and timestamp validation.

### Changed

- `SessionContext` gains optional authoritative assurance.
- `MappedClaims` gains optional host-accepted assurance. Built-in and no-op
  mappers leave it absent; provider claims never imply local MFA by default.
- `StoredRefreshToken` gains optional `refreshable_metadata`; assurance is
  stored in its existing `session` value. Both fields deserialize safely when
  absent.
- Refresh rotation reconstructs `auth_time`, `amr`, `acr`, MFA state, and the
  allowlisted session metadata without changing the original authentication
  time.

### Security

- Recent-MFA evaluation requires signed token assurance claims to match the
  authoritative session assurance and fails closed on missing, inconsistent,
  future, stale, or arithmetically unsafe timestamps.
- Per-token `jti`, expiry, purpose, confirmation (`cnf`), resource bindings,
  and arbitrary claims are deliberately regenerated or omitted on refresh.
- Assurance denials expose one safe client message; diagnostic detail remains
  server-only and is omitted from `Debug`.
- Crate publication is disabled; distribution remains Git-only.

### Migration / SemVer

`0.8.0` is a pre-1.0 minor with public-struct and persisted-record additions.
Hosts using struct literals or relational refresh-token schemas must migrate.
The `RefreshTokenStore` trait signatures are unchanged. See
[MIGRATION.md](MIGRATION.md) and [session assurance](docs/session-assurance.md).

## 0.7.0

### Added

- `AccessTokenValidator` for store-free resource-server JWT validation using
  static RS256 public PEM, static JWKS JSON, key resolvers, or explicitly
  enabled HS256.
- Shared access-token decode core used by both `AuthService` and
  `AccessTokenValidator`.
- Validator policies: algorithm allowlist, multi-audience, bounded leeway,
  purpose policy, bearer parse mode, claim requirements, injectable clock.
- `ScopeMatch`, `ExactScopeMatch`, `HierarchicalScopeMatch`,
  `HierarchicalScopeOptions`, `ScopeMatcher`, and `AuthRuntime`.
- Language-neutral scope golden vectors in `testdata/scope_match_golden.json`.
- Matcher-aware `has_scope_with`, `has_any_scope_with`, and
  `has_all_scopes_with` helpers on `AuthUser`, `ApiTokenPrincipal`, and
  `AuthPrincipal`.
- Guard runtime matching for scope and principal scope guards, with exact fallback.
- `AuthService::with_scope_matcher` and `AuthService::scope_matcher`.
- `AuthService::issue_access_token_only` with `AccessTokenOnlyRequest` and
  `AccessTokenOnlyGrant` (no refresh-token row; unique `jti`; TTL bounds).
- `CombinedAuth` and `AccessTokenAuth` for endpoints that accept user JWTs or
  API tokens and inject one `AuthPrincipal`.
- Optional multi-tenant / sender-binding claims via `AccessTokenMetadata`,
  `ClaimRequirements`, `ActorIdentity`, and `ConfirmationClaims`.
- Key resolver abstractions: `AccessTokenKeyResolver`, `StaticRs256Key`,
  `StaticJwksKeySet`, `StaticHs256Key`, `RotatingJwksKeySet`.
- `TokenStatusChecker`, `ReauthorizationPolicy`, and related status types.
- Structured authorization decision hooks (`AuthorizationDecision`,
  `AuthorizationDecisionHook`) that cannot override deny decisions.
- Safe public error contract: `public_code()`, `public_message()`,
  `internal_detail()`.
- `ChannelIdentity`, `channel_identity_from_ctx`, and `RequireChannelScheme`.
- Documentation for resource servers, scope matching, multi-tenant claims, key
  rotation, access-token-only grants, WebSocket reauthorization, public errors,
  combined auth, and migration.

### Changed

- Renamed the public MFA enum to `MfaFactor` to avoid a product-vocabulary
  substring false positive in source scans. Serialized `SessionContext` data is
  unchanged.
- Access tokens now include a unique `jti` and optional standard metadata fields.
- `AuthUser` gains `token_claims: AccessTokenMetadata` (default empty for
  callers that construct the struct in tests).
- `AuthConfig` gains `max_access_token_ttl` (default 24 hours).
- Hierarchical bare `*` no longer matches unless `allow_universal_wildcard`.
- GraphQL `ErrorExtensions` emit only safe public messages and codes.
- `AuthService::inject_http_auth` now also injects `AuthRuntime` on successful
  authentication.
- `AccessTokenValidator::inject_http_auth` injects `AuthUser`,
  `AuthPrincipal::User`, and `AuthRuntime`.
- Guards use `AuthRuntime` when present and exact matching otherwise.

### Security

- Resource-server validation fails closed by default.
- HS256 resource-server validation is rejected unless `accept_hs256(true)`.
- Algorithm confusion is prevented by configured algorithm allowlists.
- Expired JWTs never fall through to API-token authentication in `CombinedAuth`.
- Invalid tokens never become anonymous.
- Secret-bearing grant/payload types redact `Debug`.
- Public GraphQL errors no longer include OIDC/store/configuration internals.

### Behavioral Compatibility

- Exact matching remains the default and existing exact helpers are unchanged.
- `super_scopes` default to an empty list.
- Hierarchical matching is opt-in.
- Purpose policy defaults to accepting legacy tokens missing `purpose`.
- Bearer parse mode defaults to accepting raw tokens without a scheme.
- Claim requirements default to none.

### Migration

See [MIGRATION.md](MIGRATION.md) for old-to-new API mappings, behavioral
classification, WebSocket reauthorization expectations, and the scope matcher
golden table.

### SemVer Recommendation

Publish as **0.7.0**. This is a minor release under 0.x conventions with additive
APIs and deliberate hardening. Treat GraphQL public error messages and
`AuthUser` construction as breaking for consumers that depended on previous
behavior; document upgrades via the migration guide.

Pin Git consumers (for example Gema) to the annotated `v0.7.0` tag SHA on
`main`, not to a vendored tree.
