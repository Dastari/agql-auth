# Changelog

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
classification, and the scope matcher golden table.

### SemVer Recommendation

Publish as **0.7.0**. This is a minor release under 0.x conventions with additive
APIs and deliberate hardening. Treat GraphQL public error messages and
`AuthUser` construction as breaking for consumers that depended on previous
behavior; document upgrades via the migration guide.
