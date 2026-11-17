# Changelog

## 0.27.0

Security release covering credential counting, refresh sessions, access-token
validation, delegation, single-use tokens and the OIDC/OAuth 2.0 clients. This is a
breaking pre-1.0 minor: store traits gain required methods, defaults are stricter and
some error codes change. Read MIGRATION.md, including its upgrade order, first.

### Security

- A full or failing rate-limit store no longer leaves credential attempts uncounted.
  Password login, TOTP and login codes reserve the attempt on every key before any
  secret is checked and fail closed with `AUTH_SERVICE_UNAVAILABLE`. Concurrent
  bursts can no longer verify more attempts than the lockout budget allows.
- The shared client (IP) bucket is checked before every credential check but records
  only failed checks, so concurrent correct logins behind one NAT never throttle each
  other, and a success never clears failures recorded from that address. Success
  clears only the principal bucket. Request flows record nothing when any key is
  throttled.
  Known accounts are counted by local user ID, so aliases share one budget.
- `USER_DISABLED` is returned only after the correct password. Unverifiable stored
  hashes do dummy Argon2 work and return `INVALID_CREDENTIALS`. Passwords over
  `max_password_bytes` (default 1024) are never hashed, and dummy work uses the
  configured Argon2 parameters (#38).
- A failed password-worker spawn is no longer cached for the process lifetime (#39).
- `verify_login_challenge_for` refuses a challenge for another principal or channel
  before it spends an attempt (#27). `step_up_session` refuses an empty method list
  and `RecentMfaPolicy` rejects MFA that records no method (#34, #41).
- `logout(token, false)` with a superseded refresh token revokes the family as
  `ReplayDetected`, and a rotation racing the call no longer survives it.
- Neither rotation nor any access token extends a session past
  `max_session_lifetime` (default 90 days): access-token expiry is capped at the
  session's absolute deadline as well as the refresh token's.
  New `AuthService::revoke_user_sessions` ends all of a user's refresh sessions, and
  consuming a password-reset token now calls it (#33).
- The `RefreshTokenStore` concurrency rules (rotation serialized with family
  revocation, update-first compare-and-swap, revoked rows unchanged) apply to every
  store, not only reuse-grace adopters.
- `graphql_refresh_cookie_directive` blanks the refresh token in aliased, nested,
  incomplete and partial-error responses. It sanitizes the response in place, so
  keys keep their selection order, and leaves hex digests alone.
- `AuthError`'s `Display` is the public message; internal detail goes only through
  `diagnostic()`, `internal_detail()` and `Debug` (#28).
- Access tokens need `typ`, `purpose` and the standard `scope` claim by default.
  `Authorization` values need the `Bearer` scheme in the validator (by default),
  `AuthService`, `ApiTokenService` and `CombinedAuth`, and in the `authorization`
  connection-init key; `access_token`/`accessToken` keys carry the bare token (#32). HMAC algorithms need `accept_hs256(true)`
  on every validator path, including custom key resolvers and HS384/HS512.
- JWKS keys verify only their own algorithm; `oct` keys, duplicate `kid`s and
  unidentified keys in multi-key documents are refused (#30). Stale keys stop
  verifying after a bounded `max_stale` window (#29).
- Default guards refuse session-bound delegations and `actor` tokens unless they call
  `allow_delegated()`. `require_cnf` verifies the presented certificate or key
  thumbprint, not just the presence of `cnf`.
- A trailing scope wildcard matches whole segments only (`tenant.1*` no longer covers
  `tenant.10.read`), and empty requirement lists deny (#35).
- Purpose tokens carry a `jti` and can be consumed once (#34).
- A resolved delegation reference never carries more than the delegated token's
  grants, expiry and assurance; an expired reference, or one without an expiry, is
  refused instead of inheriting the parent session's lifetime. Every session-bound delegation needs an enabled parent.
- Reset tokens must carry the reset `typ` and are always recorded. Only a user's
  newest outstanding token can be consumed, and consuming it invalidates the rest.
- API-token authentication enforces the stored audience and a configured resource.
- `Debug` no longer prints login codes, credential or token hashes, or the refresh
  token in `GraphqlRefreshCookieDirective::Set`.
- OIDC and OAuth 2.0 logins refuse disabled and missing local users before linking an
  identity or issuing a session. OAuth state is bound to the initiating browser.
- OIDC discovery requires `https` endpoints and an exact issuer; Entra tokens must
  match the signing key's JWKS `issuer`. RFC 9207 `iss` is checked, `private_key_jwt`
  assertions target the issuer and live at most ten minutes, `exchange_code` and
  `fetch_profile` are crate-private, and client credentials are zeroized (#40).

### Breaking changes

- Required store methods: `RefreshTokenStore::revoke_refresh_tokens_for_user`,
  `PasswordResetTokenStore::invalidate_password_reset_tokens_for_user`.
  `OAuthStateStore` must persist `browser_binding_hash`. Default `ApiTokenStore` bulk
  revocation returns `InvalidConfiguration` instead of `Ok(0)`.
- New public fields on `AuthConfig`, `StoredRefreshToken`, `KeyRefreshPolicy`,
  `IssuedPurposeToken`, `VerifiedPurposeToken`, `PrincipalReference`,
  `RecentMfaPolicy`, `OidcProviderConfig`, `OidcCallbackInput`, `OAuthLoginState` and
  `OidcAuthorizationRequest`. `RequireAuth` and `RequirePrincipal` are not unit structs.
- New variants: `AuthError::{PasswordTooLong, PurposeTokenReplayed}`,
  `ClaimRequirementError::{ConfirmationMismatch, ConfirmationNotPresented}`,
  `AuthMethod::OAuth2`.
- `issue_password_reset_token` is async and takes the store;
  `issue_password_reset_token_with_ttl` and both `code_verifier` request fields are
  removed; `exchange_code` and `fetch_profile` are crate-private. Provider configs and
  token responses implement `Drop`. `AuthError` `Display` text changed.
  `CombinedAuth` and `ApiTokenService` are no longer `UnwindSafe`/`RefUnwindSafe`.
- `AuthService::authenticate_bearer`, `inject_http_auth`,
  `authenticate_session_management_bearer`, `ApiTokenService::authenticate_bearer`
  and `CombinedAuth::inject_http_auth` refuse a bare token with
  `INVALID_BEARER_TOKEN`; pass bare tokens to `authenticate_access_token` /
  `authenticate_token`.
- Stricter defaults: `PurposePolicy`, `BearerParseMode`, `LegacyScopeClaims`,
  `OAuthBrowserBinding`, a 90-day session lifetime and a 1024-byte password cap.
  Golden scope vectors move to version `2.0`.
- Looser default: `KeyRefreshPolicy::default()` is now `UseStale` with a one-hour
  `max_stale` (it was `Reject`, contrary to the docs), so after a failed JWKS refresh
  cached keys, including withdrawn ones, keep verifying for up to
  `cache_ttl + max_stale` (about 65 minutes by default). Set
  `stale_policy: StaleKeyPolicy::Reject` to keep failing closed (#29).
- Error codes: disabled-with-wrong-password and unverifiable hashes give
  `INVALID_CREDENTIALS`; foreign-audience API tokens `INVALID_API_TOKEN`; pre-0.27
  delegation references and unprovisioned external users `FORBIDDEN`.
- Behaviour: see Security for sign-out, guards, `require_cnf` and wildcards.
  `ResolvedPrincipal::principal()` for a delegation is the narrowed view; delegation
  and external login need the user in the `UserStore`; known-account counters use a
  new key; request flows get at most half of a `MemoryAuthRateLimitStore`.
- Stricter validation of challenge, TOTP, OIDC/OAuth 2.0, JWKS and TTL settings,
  short TOTP secrets, reserved purpose-token claims, and `LegacyArray` scope claims
  without `LegacyScopeClaims::Accept`. `with_refresh_rotation_clock` now drives all
  session-clock time (#38).

### Added

- `AuthService::{revoke_user_sessions, consume_purpose_token,
  verify_login_challenge_for, with_password_work_pool, password_hash_needs_rehash,
  with_session_clock, with_clock}`, `ApiTokenService::with_clock` (#38).
- `AuthConfig::{max_session_lifetime, password_hashing, previous_verification_keys}`,
  `with_previous_verification_key`, `PasswordHashingConfig`, `PasswordWorkPool`,
  `PasswordWorkPoolConfig` and their limit constants (#31, #33, #39).
- `AuthError::diagnostic()`, `AccessTokenValidatorBuilder::key_ids`,
  `KeyRefreshPolicy::max_stale`, `RotatingJwksKeySet::needs_refresh`.
- `PresentedConfirmation`, `AccessTokenMetadata::{verify_confirmation, is_delegated}`,
  `ClaimRequirements::validate_with_confirmation`, `*_with_confirmation` validator
  methods and `allow_delegated()` on user and principal guards.
- `RoleScopeCatalogue::{hierarchical_scope_match, apply_exact_only}`,
  `PurposeTokenReplayStore`, `DelegationGrantCeiling`, `LoginChallengeExpectation`,
  `RecentMfaPolicy::{new, required_amr, required_context}`.
- `ApiTokenService::{with_expected_audience, with_expected_resource,
  with_touch_observer}` and `ApiTokenTouchObserver`.
- `OAuth2Provider::login_with_callback`, `OAuth2UserProvisioner`,
  `OAuthBrowserBinding`, provider `issuer` settings, `OidcCallbackInput::{with_issuer,
  with_browser_binding}`, `ClientJwtClaims` `x5t#S256` and `nbf`, OAuth limit constants.
- Bounds: challenge `code_length` 6 to 12 and `max_attempts` 1 to 10; TOTP period 15
  to 300 s, skew at most 2, secrets 20 to 64 bytes generated and 16 required (#38).

### Fixed

- Service-side issuance, validation, logout and revocation time comes from the
  session clock; OIDC ID-token `exp`/`nbf` use the provider clock (#38).
- `KeyRefreshPolicy::default()` matches the docs (#29; see the looser default under
  Breaking changes). Static JWKS key handling
  follows the docs, and multi-key rotation works without `key_id` (#30).
- Key-refresh durations saturate; a failed API-token touch no longer fails
  authentication; mixed `allowed_id_token_algs` fail at configuration time.
- Negative `expires_in`, fragment or non-`https` redirect URIs and `state_ttl` over an
  hour are refused; over-long profile values are dropped (#40).
- `MemoryAuthRateLimitStore` keeps half its capacity for credential flows. The
  password pool is sized from available parallelism (#39).
- `AuthPrincipal::expires_at()` returns the access-token expiry, `access_token_ttl`
  may not exceed `max_access_token_ttl`, `internal_detail()` covers
  `InvalidOidcAuthorizationOptions`, `exact_only` catalogue flags can be enforced and
  MFA AMR lists match case-insensitively (#38).
- Store docs state required atomicity with portable SQL, and contradictory sign-out
  and delegation-reference docs are fixed (#38).

### Dependencies and repository

- Upgrade `jsonwebtoken` to 11.1 (matching graphql-orm-router, removing a
  duplicate) and the `tokio` dev-dependency to 1.54.1 (RUSTSEC-2026-0386).
- Remove the direct `rsa` dependency; RS256 JWKS `n`/`e` are derived through
  `jsonwebtoken`. RUSTSEC-2023-0071 (rsa 0.9) and RUSTSEC-2026-0387
  (crypto-bigint 0.5) remain reachable only through `jsonwebtoken`'s
  `rust_crypto` backend; dispositions are in `docs/dependency-advisories.md`.
- Declare `rust-version = "1.90"` and `#![forbid(unsafe_code)]`.
- CI runs `cargo audit`; add Dependabot, `CODEOWNERS` and `SECURITY.md`
  (private vulnerability reporting). Drop the redundant `--no-default-features`
  lane: the crate has no features and the release script refuses to add one.
- Add a direct `zeroize` 1 dependency (already in the lock graph through
  `jsonwebtoken`; no new crate is downloaded).
- Add `tests/public_api.rs`, an external-consumer suite that implements host
  stores outside the crate and covers login, validation, rotation, replay,
  sign-out everywhere and error redaction through the public API (#38).

## 0.26.0

- Add an opt-in grace window for reuse of a just-rotated refresh token, off by
  default: `AuthService::with_refresh_reuse_grace` and `MAX_REFRESH_REUSE_GRACE`
  (30 seconds). Inside the window, a token superseded by rotation gets a new token
  and the family's newest token is rotated out in the same store transaction, so
  the family keeps one live token. Losing the rotation race follows the same rule.
  Outside the window, reuse is replay as before.
- Add the optional `RefreshTokenStore::find_live_refresh_tokens_in_family`. Its
  default reports no support, which behaves as if the window is off. Stores need no
  new column and no new write operation; overriding it adds requirements listed in
  `docs/refresh-reuse-grace.md`.
- Add `RefreshReuseGraceObserver`, `RefreshReuseGraceEvent` and
  `AuthService::with_refresh_reuse_grace_observer`, so hosts can tell a grace reuse
  from a rotation. Events carry IDs and never a token or hash.
- Add `AuthService::with_refresh_rotation_clock`, which defaults to the system clock.
- A grace reuse never exceeds rotation: disabled users, current authority, legacy
  grants and assurance apply as usual, and it cannot regain a grant the newest token
  has lost. The theft cost and its bound are in `docs/refresh-reuse-grace.md`.
- No breaking change. Existing APIs, errors, store calls, tokens and configuration
  behave as before for hosts that do not opt in. No persistence or wire migration
  is required.

## 0.25.0

- Add `FixedAudienceDelegation` and
  `AuthService::into_shared_with_fixed_audience_delegation`: an owner-created,
  startup-only facade that issues session-bound delegated tokens for one private
  audience. It holds a weak reference to the owner, so keys, configuration,
  stores, resolver, scope matching, abuse state and clocks are shared, and only
  `aud` differs. It runs the existing preparation and second authoritative read,
  keeps the same expiry caps, and creates no refresh row or idle extension. At
  both reads it also requires a current, enabled parent in the owner's `UserStore`.
- The audience is selected only by consuming the service at startup, and
  `issue_purpose_token` refuses it on that owner. Requests are bound to the path
  and audience that prepared them. RS256 owners with an active-session resolver are
  required; a retired owner makes its facade fail closed with
  `AuthServiceUnavailable`.
- Existing APIs, tokens and configuration behave as before for hosts that do not
  use the facade. No persistence or wire migration is required.

## 0.24.0

- Breaking build-feature change: stop enabling async-graphql default features
  transitively. Auth requires no named async-graphql features. Hosts using
  email validation, GraphiQL, playground, dynamic schemas or tempfile uploads
  must enable those features directly; see MIGRATION.md. Cargo feature
  unification remains additive.
- Auth public APIs, guards, context, errors/redaction, tokens, cryptography,
  MFA/OIDC, request/response behavior, storage and concurrency are unchanged.
  No persistence or wire migration is required.
- Add independent minimal and explicit additive GraphQL consumer fixtures and
  resolved-graph assertions. The MIT grant and license file are unchanged.

## 0.23.0

- Add `OAuth2Provider` for OAuth 2.0 authorization-code + PKCE providers
  without OpenID Connect (for example GitHub, `OAuth2ProviderConfig::github`).
  It reuses one-time hashed state, exchanges the code, and resolves a typed
  `OAuth2UserProfile` from a bearer userinfo request: required JSON-pointer
  subject (string or integer), email, `email_verified` (pointer, unknown or
  provider-verified), name, picture and raw JSON, plus an optional
  verified-email list (primary/first verified). No nonce; no token storage.
- Add opt-in `OidcProviderConfig::response_mode` (`query` default,
  `form_post`). The mode is sent, bound into `OAuthLoginState::response_mode`,
  and enforced by the new `handle_callback_in_mode` /
  `login_with_callback_in_mode`; mismatched delivery is refused.
- Add `TokenEndpointAuthMethod` (`client_secret_post` default,
  `client_secret_basic`, `private_key_jwt`) for both providers, and
  `ClientJwtSigner` (ES256/ES384/RS256/PS256) minting a fresh RFC 7523 client
  assertion or signed client secret (Sign in with Apple) per token request.
  `iat` is backdated by a configurable `issued_at_skew` (default 30 s) and
  `exp - iat` stays within the configured lifetime (at least 1 s).
  Keys stay in memory, are never serialized and are redacted from `Debug`.
- Add `ValidatedOidcClaims::email_verified`, accepting a JSON boolean or the
  exact strings `"true"`/`"false"`.
- Add header-aware `OidcHttpClient` methods with fail-closed defaults; token
  requests that send headers include `Accept: application/json`.
- Add distinct OAuth 2.0 errors: `OAuthProviderError`, `OAuthCallback`,
  `OAuthTokenExchange`, `OAuthUserInfo` and `OAuthMissingSubject`, mapped to the
  existing stable public codes without provider text.
- Hardening: `OidcProvider` refuses consumed states with an empty nonce.
  `OidcProviderConfig`/`MicrosoftEntraConfig` `Debug` now redact
  `client_secret`, and `client_secret` is no longer serialized. It is still
  deserialized, including from `OAuth2ProviderConfig`.
- Breaking: new public fields on `OidcProviderConfig`, `OAuthLoginState` and
  `ValidatedOidcClaims` break struct literals, new `AuthError` variants break
  exhaustive matches, stores must persist `OAuthLoginState::response_mode`,
  and serialized OIDC/Entra configurations no longer include `client_secret`.
  See MIGRATION.md.

## 0.22.1

- Admit large host-signed role catalogues whose compact JWS embeds the catalogue.
  Keep a finite 2 MiB signature ceiling and all catalogue, cryptographic binding,
  audience and lifetime checks. Hosts still bound the complete transport envelope.

## 0.22.0

- Add `ResolvedPrincipal::from_current_session` for explicit ordinary-session
  authority proof with the exact original credential reference and a distinct
  current deadline/version. Keep the strict legacy constructor path.
- Sensitive revalidation still checks original-token status and intersects exact
  scope, scalar-role and authorization-role ceilings without replacing bindings.

## 0.21.3

- Add read-only `AccessTokenValidator::current_time` so transport expiry
  scheduling can observe the same injected clock as stateless token validation.
- No constructor, validation, stored-record or token-format changes.

## 0.21.2

- Documentation only: clarify trusted-host issuance, TOTP replay/attempt limits,
  validation-only password-reset checks and optional no-op bulk revocation.
- Link complete host-bound flows and compile-check the challenge-to-session
  example. No runtime behavior, public signature or stored-record change.
- Patch metadata follows the source-path release rule for Rustdoc-only edits.

## 0.21.1

- Move async password login and challenge hashing/verification to one runtime-neutral,
  process-wide bounded worker pool (two workers, 32 queued jobs). Saturation and
  executor failures return `AuthServiceUnavailable` without credential-failure counts.
- Keep admitted work charged until completion after caller cancellation. Preserve
  disabled-account dummy verification and atomic challenge reservation semantics.
- Re-read current enabled user credentials/grants before session creation and
  reject challenges that expire in the worker queue before Argon2 starts.
- Document explicit synchronous password helpers and host input/cost admission boundaries.

## 0.21.0

- Require atomic login-challenge attempt admission before password work, closing
  concurrent guesses beyond the configured budget. All admitted attempts count,
  including successful, cancelled, or interrupted work; no refunds or fallback.
- Recheck challenge expiry after expensive work and asynchronous consumption,
  with a separate injectable trusted challenge clock. Challenge definitions are
  immutable and checked for coherence across admission.
- Breaking `LoginChallengeStore` and `StoredLoginChallenge` contract: implement
  reservation and conditional consume; migrate as described in MIGRATION.md.

## 0.20.3

- Reject empty issuer/audience, nonpositive or unrepresentable configured
  lifetimes, and JWT expiries that round into the issuance second. Use checked expiry
  arithmetic for session, API, purpose, challenge, and password-reset tokens.
- Reject unrepresentable signed access-token timestamps and use wide arithmetic
  for leeway checks, preventing overflow and loss of expiry metadata.
- Invalid or overflowing connection reauthorization schedules require an
  immediate check. See MIGRATION.md for invalid-configuration behavior changes.

## 0.20.2

- Preserve the original Authorization header when `CombinedAuth` delegates a
  user JWT to its validator. `RequireBearer` now accepts a valid Bearer header
  through the combined injector while still rejecting a raw JWT. API-token
  selection and expired/invalid JWT failure behavior are unchanged.

## 0.20.1

- Bound default process-local abuse state to 16,384 records and reclaim expired
  records on every operation. Configurable capacity and a shared injected clock
  support deterministic single-process hosts.
- Preserve atomic compare-and-swap and active lockouts: capacity exhaustion fails
  closed for new distinct keys; existing records can update or clear. Expiry
  indexing remains bounded under repeated counter updates.
- No durable store trait methods or serialized records change. See MIGRATION.md
  for capacity and clock behavior.

## 0.20.0

- Refresh rotation intersects prior roles/scopes with current authority. Password
  sessions use StoredUser; host/OIDC sessions require RefreshGrantAuthority.
  Typed authorization roles also retain a persisted, monotonically narrowing
  ceiling against the current AdditionalTokenRolesProvider result.
- Persist refresh grant provenance and role ceilings; legacy records require
  reauthentication rather than silently inheriting a guessed grant source.
- Add revalidate_sensitive_principal for immediate, fail-closed current-authority
  and token-status checks while preserving accepted credential bindings.
- Breaking storage/refresh migration: see MIGRATION.md.

## 0.19.2

- Pin CI and release actions to full revisions while preserving explicit token
  permissions and all validation lanes. Workflow maintenance only; no API or
  consumer migration change.

- Disabled password-login attempts now perform the existing dummy Argon2
  verification and consume configured principal/client credential controls
  through the engine's CAS recorder, including correct-password attempts.
- Preserve `UserDisabled` / `USER_DISABLED` for admitted disabled attempts;
  active backoff/lockout and safe persistence errors retain precedence.
  Disabled attempts never clear counters or enter token/session issuance.
- Add deterministic password-work/issuance assertions and executable SQLite
  and PostgreSQL consumer-store conformance fixtures in CI.
- No public API, token format, store contract, production dependency, or schema
  change. See the migration guide and password-login review for behavior notes.

## 0.19.1

- Declare the MIT license and include its full text, matching graphql-orm.
- Library source, public API, token formats, and runtime behavior are unchanged.

## 0.19.0

### Added

- `HierarchicalScopeOptions::allow_super_scopes_for_exact_only` and its
  builder let hosts explicitly permit configured super-scopes to satisfy
  exact-only requirements.
- Language-neutral golden vectors and Rust truth-table coverage for multiple
  super-scopes, exact grants, wildcard grants, unrelated grants, and similar
  but unconfigured strings.

### Security

- Exact-only requirements continue to reject every wildcard-derived match.
  Super-scopes are recognized by exact configured membership only.

### Compatibility / SemVer

- The new policy is disabled by default, preserving 0.18 matcher decisions.
  Existing exact-only requirements continue to accept only direct exact grants
  until a host opts in. The additive option makes a pre-1.0 minor release.
- No token, database, role, or stored-scope migration is required.

## 0.18.0

### Added

- `AdditionalTokenRolesProvider` for host-owned refreshable-session membership
  resolution and a distinct typed `authorization_roles` access-token claim.
- Default-and-builder-based signed-catalogue validation options that decouple
  maximum issuer lifetime from refresh cadence and allow bounded clock skew.

### Security and availability

- Static expansion now returns an explicit unknown-role error. Remote
  consumers can refresh immediately and fail closed instead of silently
  authenticating with none of an unknown role's scopes.
- Sessionless and session-bound delegation issuance do not invoke the
  additional-role provider, so the new hook cannot widen those grants.

### Compatibility / SemVer

- The provider and claim are opt-in. Existing issuers emit no new claim and
  existing tokens decode with an empty authorization-role set. Consumers that
  use exhaustive `AccessTokenMetadata` literals must initialize the additive
  field or construct from `Default`.
- Hosts using role expansion should pass only the distinct authorization-role
  set. Unknown identifiers now return an error instead of being ignored.

## 0.17.1

### Changed

- Newly serialized `SessionContext` values omit the default unsatisfied MFA
  object and absent active business scope. Deserialization continues to
  default both fields, while non-default MFA and active-scope values retain
  their existing wire shape.

### Compatibility / SemVer

- This output-only patch reduces access-token size for every consumer. Typed
  `agql-auth` readers and existing stored session documents remain compatible;
  consumers that assert literal JSON should accept the already-supported
  omission of these default-valued fields.

## 0.17.0

### Added

- `RoleScopeExpansionProvider`, `StaticRoleScopeExpansion`, and
  `effective_scopes` for deterministic host-supplied role expansion.
- Bounded, versioned `RoleScopeCatalogue` scope/role definitions plus neutral
  signed-envelope and claims types for host-owned transport and verification.

### Security

- Catalogue validation rejects duplicate IDs, unregistered role scope
  references, invalid values, excessive counts, mismatched signed claims, and
  invalid lifetimes. At this release, unknown token roles contributed no
  authority; 0.18.0 tightens that case to an explicit error. Providers have an
  explicit unavailable result for fail-closed caches.
- The crate supplies no policy values, network client, signing key, membership
  schema, cache authority, or consumer-specific identifier.

### Compatibility / SemVer

- The new contract is additive and opt-in. Existing role claims, direct scopes,
  validators, guards, stores, and exact/hierarchical matchers are unchanged.
- Hosts choose whether and where to expand verified roles. This capability is a
  pre-1.0 minor release and requires no default database or token-wire migration.

## 0.16.0

### Added

- `HierarchicalScopeOptions::exact_only_scopes`, a consumer-supplied set of
  required scopes that accept only an exactly equal grant.
- `HierarchicalScopeOptions::exact_only_scope_patterns` for selecting
  resource-qualified exact-only families under the configured wildcard rules.
- `HierarchicalScopeOptions::with_*` construction methods and structured
  validation errors/warnings. The options type is non-exhaustive so adding a
  future option does not break consumer construction.
- Neutral golden vectors and a super-scope/wildcard/exact-grant matrix for
  ordinary and exact-only requirements.

### Security

- Exact-only requirements are evaluated before configured super-scopes,
  universal wildcards, trailing wildcards, or segment wildcards. The crate
  supplies no policy values and continues to default to an empty set.
- Validation rejects a bare-wildcard exact-only pattern and reports every
  other wildcard-bearing exact-only pattern so hosts can expose subtree-wide
  policy during configuration loading.

### Compatibility / SemVer

- Matcher behavior is unchanged for valid constructor and default users.
  `HierarchicalScopeMatch::new` and `ScopeMatcher::hierarchical` now return a
  validation `Result`; consumers should migrate struct literals to the
  `Default`-based `with_*` construction methods. This constructor hardening and
  the exact-only additions make a pre-1.0 minor release.
- No token, database, refresh-store, role, or scope-claim migration is
  required. Consumers can use the same generic mechanism for sensitive
  operation scopes while retaining their own naming and policy catalogue.

## 0.15.0

### Added

- `SessionBoundAccessTokenOnlyRequest`,
  `SessionBoundDelegationBinding`, and
  `AuthService::prepare_session_bound_access_token_only` /
  `issue_session_bound_access_token_only` for short-lived, non-refreshable
  delegation from an existing active user session.
- `VerifiedActiveUserSessionResolver` and opaque
  `VerifiedActiveUserSession` for the mandatory read-only authoritative
  session recheck performed inside `AuthService` immediately before signing.
- Closed `AccessTokenGrantKind` values, including
  `session_bound_delegation`, plus authoritative `session_version` and typed
  `ExactOperationBinding` access-token claims.
- `AuthConfig::max_session_bound_delegation_ttl`, defaulting to 15 minutes,
  and the corresponding builder.
- Resource-server claim requirements for exact grant kind, session version,
  and operation-binding presence.
- `AuthUser::require_session_management_eligible` and
  `AuthUser::is_session_bound_delegation` classification helpers, plus
  session-management-specific bearer authentication on both issuer and
  resource-server validators.

### Security

- Session-bound issuance cannot accept an `AuthUser`, `AuthPrincipal`, raw
  subject, raw session ID, or caller boolean as verification proof. The
  initially resolved principal supplies only a reference. Preparation reads
  and stamps the authoritative version; issuance reads it again through the
  trusted resolver configured at application startup and checks current
  session status, identity, version, authority, assurance, tenant, and
  lifetime.
- Revocation, expiry, subject/session/version changes, and role/scope reductions
  between initial resolution and issuance fail closed. Roles use exact subset
  matching; scopes use the trusted `AuthService` matcher configured at startup.
- Delegated expiry is clamped to requested TTL, the delegation ceiling, and
  remaining absolute/idle session lifetime. The resolver contract prohibits
  extending idle expiry or interactive last-active state.
- Actor, resource, correlation, and exact registered-operation bindings are
  mandatory signed claims. Confirmation binding remains optional but validated
  when supplied. Existing actor, confirmation, or resource bindings cannot be
  replaced by a delegated request. Reserved-claim matching is case-insensitive and includes
  common identity, session, authority, audience, timing, actor, confirmation,
  classification, resource, correlation, and operation aliases.
- Delegated credentials cannot source another delegation and are explicitly
  ineligible for session-management handlers. Each receives a unique `jti`;
  underlying session status and version remain authoritative.
- Focused coverage includes a signed-JWT-to-GraphQL-middleware-to-current-
  session-to-protected-resolver path, post-resolution races, expiry clamps,
  authority semantics, no persistence mutation, and diagnostics redaction.

### Compatibility / SemVer

- Existing `issue_access_token_only` behavior remains sessionless and creates
  no refresh record; newly issued tokens now carry `grant_kind = sessionless`.
  Normal refreshable access tokens carry `grant_kind = user_session`.
- The new delegation contract is opt-in. Hosts that do not configure an active
  session resolver cannot issue session-bound delegations.
- `AuthConfig`, `AccessTokenMetadata`, `ClaimRequirements`, and
  `PrincipalReference` have additive public fields. Exhaustive struct literals
  and exhaustive matches must be updated. These public and JWT-wire additions
  make this a pre-1.0 minor release.
- No database or refresh-store migration is required. Hosts adopting the new
  contract must expose their existing authoritative session/security version
  through the resolver and compare it on delegated request assurance.

## 0.14.0

### Added

- `AccessTokenScopeClaimFormat` and
  `AuthConfig::with_access_token_scope_claim_format` for selecting standard
  `scope` issuance or temporary pre-0.14 `scopes` array issuance during a
  rolling migration.
- `LegacyScopeClaims`, `AuthConfig::with_legacy_scope_claims`, and
  `AccessTokenValidatorBuilder::legacy_scope_claims` for independently
  controlling whether locally validated access tokens may contain the legacy
  array.
- Public access-token scope bounds:
  `MAX_ACCESS_TOKEN_SCOPES`, `MAX_ACCESS_TOKEN_SCOPE_LENGTH`, and
  `MAX_ACCESS_TOKEN_SCOPE_CLAIM_LENGTH`.
- A long-form [access-token scope claim migration guide](docs/access-token-scope-claims.md)
  covering staged deployment, rollback, strict-mode activation, and the wire
  compatibility boundary.

### Changed

- Newly issued access tokens now use the standard OAuth space-delimited
  `scope` string. Empty scope sets omit the claim. The public
  `AuthUser::scopes` representation and authorization helpers remain a
  `Vec<String>` and preserve stable first-seen order.
- Access-token validation accepts the pre-0.14 `scopes` string array by
  default so old tokens remain usable during their bounded lifetime. After the
  migration window, hosts can set `LegacyScopeClaims::Reject` independently on
  issuers and resource-server validators.
- Tokens that carry both `scope` and `scopes` validate only when legacy support
  is enabled and the two claims describe the same set. Conflicting dual claims
  are rejected.
- Access-token scope values now use one bounded wire grammar across standard
  and legacy claims: printable ASCII excluding space, double quote, and
  backslash; at most 256 values, 512 bytes per value, and 16 KiB aggregate.

### Security

- Malformed, empty, non-ASCII, control-character, over-count, oversized, and
  conflicting access-token scope claims fail closed before an `AuthUser` is
  constructed.
- `scope` and `scopes` are both reserved access-token claim names, preventing
  flattened custom metadata from shadowing either migration format.
- Invalid scope values fail token issuance without reflecting the rejected
  value in the error.

### Breaking Changes / Compatibility

- The default access-token wire representation changes from
  `"scopes":["users.read"]` to `"scope":"users.read"`. Consumers that decode
  JWT payloads themselves must accept the standard claim before issuers adopt
  the new default, or issuers must temporarily select
  `AccessTokenScopeClaimFormat::LegacyArray`.
- `AuthConfig` has two new public fields. Code that creates configuration
  through constructors or builder methods continues to compile;
  exhaustive `AuthConfig` struct literals must initialize the new fields.
- Previously issued well-formed legacy access tokens remain valid under the
  default `LegacyScopeClaims::Accept` policy. No refresh-token, user-store,
  rate-limit-store, or database migration is required.
- Purpose tokens retain their purpose-specific `scopes` array. API/service
  tokens remain opaque, and their scope model is unchanged.
- These intentional wire and public-struct changes make `0.14.0` a pre-1.0
  minor release. Follow the staged [migration guide](MIGRATION.md) before
  enabling strict legacy rejection.

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
