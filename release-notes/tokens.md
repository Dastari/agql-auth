# Stream `tokens`: access tokens, keys, claims, guards, scopes, errors

Branch commits (on top of `1b23caa`):

- `284cfb2` fix: make AuthError Display the safe public message
- `e00f23d` fix: match scope wildcards by whole segment and enforce catalogue exact-only flags
- `ce7ca0a` fix: refuse delegated tokens in default guards and verify cnf possession
- `64349e3` fix: harden access-token validation defaults, key handling and purpose tokens

## Findings

### AUTH-15 (#28): `AuthError` `Display` carried internal detail

`AuthError` no longer derives `Display` through `thiserror`. `Display` now writes
`public_message()`, so `to_string()`, `{err}` and a resolver's plain `?` (the
blanket `From<T: Display>` conversion into `async_graphql::Error`) only ever
carry the stable generic message. The old diagnostic text, byte for byte, is
available through the new `AuthError::diagnostic()` (an `AuthErrorDiagnostic`
`Display` wrapper), `internal_detail()` and `Debug`. `internal_detail()` also
covers `InvalidOidcAuthorizationOptions` now. Every in-crate conversion into
`async_graphql::Error` already went through `ErrorExtensions::extend`
(`public_message` + `code`); public codes are unchanged. A plain `?` still
cannot attach `extensions.code` (that would need a conflicting `From` impl);
the docs say to use `.extend()`.

### AUTH-16 (#29): `KeyRefreshPolicy::default()` was `Reject`

Decision: a bounded stale-use window. `KeyRefreshPolicy` gains `max_stale`
(default 1 h) and its default is now `UseStale`, matching `StaleKeyPolicy`'s
default and the docs. Under `UseStale` keys keep verifying for `max_stale`
after `cache_ttl` while refreshes fail, then every resolve fails with
`AuthServiceUnavailable` until `replace_jwks` succeeds, so a withdrawn key
stops working within a bounded time. `Reject` keeps failing at `cache_ttl`. New
`RotatingJwksKeySet::needs_refresh()` drives periodic refresh, which the old doc
example lacked. `std::time::Duration` to `time::Duration` conversions now
saturate instead of wrapping (`as i64` on a huge duration became negative).

### AUTH-18 (#30): static JWKS builder

`StaticJwksKeySet` labels each key with its JWK `alg`, or the algorithm implied
by its key type (RSA RS256, EC P-256 ES256, P-384 ES384, Ed25519 EdDSA), instead
of RS256 for every key. It refuses `oct` keys, HMAC or encryption `alg` values,
mismatched `alg`/key types, duplicate `kid`s and unidentified keys in a
multi-key document, and skips keys whose `use` is not `sig`. A one-key document
whose JWK has a `kid` now requires that `kid` on tokens, as the docs said. The
validator no longer demands `key_id` for a multi-key document (the builder
errored before), so a JWKS with old and new keys accepts both during a
rotation. `key_id` still pins one `kid`; new `key_ids([...])` pins a set; every
pinned `kid` must exist in the document. A resolved key verifies only tokens
whose header `alg` equals its algorithm. `ResolvedKey` gets a redacted `Debug`.

### AUTH-19 (#31): verification-only previous signing keys

New `AuthConfig::previous_verification_keys: Vec<JwtVerificationKey>` (builder
`with_previous_verification_key(kid, public_pem)`, at most
`MAX_PREVIOUS_VERIFICATION_KEYS` = 8, RS256 only). Each key is parsed at
`AuthService::new`; empty, duplicate or current-`kid` entries, bad PEM, too many
keys or HS256 signing are configuration errors. `jwks()` lists the signing key
first, then the previous keys. Service-side validation selects the key by
header `kid` (`local_jwt_decoding_key`) for access tokens, the fixed-audience
delegation path, purpose tokens and password-reset tokens. Previous keys never
sign. `docs/key-rotation.md` documents the publish / switch / wait / remove
procedure.

### AUTH-20 (#32): legacy-permissive validation defaults

Checked first: every 0.26 access token carries `typ = "access"` and
`purpose = "access_token"` (`issue_access_token_with_user_for_audience` sets
both unconditionally, since 0.6.0) and the standard `scope` claim unless the
issuer opted into `AccessTokenScopeClaimFormat::LegacyArray` (non-default since
0.14). New defaults:

- `PurposePolicy::RequireAccessToken` now also requires `typ = "access"` and is
  the default (`AccessTokenOrLegacy` accepts a missing `typ`/`purpose`). The
  service's own validation uses the strict policy.
- `BearerParseMode::RequireBearer` is the default for `AccessTokenValidator`.
- `LegacyScopeClaims::Reject` is the default for the enum, `AuthConfig` and
  `AccessTokenValidator`.

`current_issuer_tokens_pass_the_strict_defaults` pins that 0.26-shaped tokens
pass every new default. `AuthService::authenticate_bearer` still accepts raw
tokens (it lives in a `service.rs` function outside this stream's scope; see
integration notes).

### AUTH-26 (#35): guard and scope edge cases

- `RequireAllRoles`, `RequireAllScopes` and `RequireAllPrincipalScopes` with an
  empty list deny. The `has_all_scopes` helpers (`scopes::has_all_scopes`,
  `ScopeMatch::has_all_scopes`, `AuthUser` / `ApiTokenPrincipal` /
  `AuthPrincipal` `has_all_scopes_with`) return `false` for an empty list.
- `HierarchicalScopeMatch` treats a trailing wildcard as a whole final segment
  with literally equal prefix segments; a wildcard inside a segment is literal;
  a consumed segment must be non-empty. `tenant.1*` no longer matches
  `tenant.10.read`. Exact-only patterns use the same rule.
- `exact_only` catalogue flags: wired, not removed. They are part of the signed
  catalogue wire format (`deny_unknown_fields`), so removal would break
  catalogues in circulation. `RoleScopeCatalogue::hierarchical_scope_match(options)`
  and `apply_exact_only(options)` build matcher options that enforce them.
- `testdata/scope_match_golden.json` moves to version `2.0`: vector 8
  (`a.b*` vs `a.bc`) flips to `false`; vectors 40 to 46 pin the segment rule. The
  only in-repo consumer is `src/tests/scope_match.rs` (its inline vector 8 is
  updated; new guard vector G11 pins the empty `all` list). External routers
  implementing these vectors must be updated together.

### AUTH-17: HS256 gate skipped for a `key_resolver`

With a custom resolver the builder derived the default allowlist from the
resolver's probe, so an HS256 key produced `allowed = [HS256]` without
`accept_hs256`. Now the HMAC gate (HS256, HS384, HS512) applies to the probe,
to `allowed_algorithms` (HS384/HS512 were not gated before) and per request to
the header `alg` and the resolved key. `validate_hs256_secret` is the one shared
length check.

### AUTH-24: `cnf` presence-only and delegated tokens as ordinary bearers

"Delegation token" = `AccessTokenMetadata::is_delegated()`: `grant_kind ==
SessionBoundDelegation` or any `actor` claim (impersonation, on-behalf-of and
sessionless grants with an actor). Every user and principal guard refuses
those unless it opts in with `.allow_delegated()`. API-token principals are
unaffected. Confirmation: `PresentedConfirmation` (certificate or JWK SHA-256
thumbprint the host verified) and `AccessTokenMetadata::verify_confirmation`
compare in constant time (SHA-256 of both values, then `subtle::ct_eq`), and
every method bound in `cnf` must match. `ClaimRequirements::require_cnf` (and
`tenant_jti_and_cnf()`) now needs presented material:
`validate()` fails with `ConfirmationNotPresented`; `validate_with_confirmation`
checks the binding. `AccessTokenValidator` gains
`authenticate_access_token_with_confirmation`,
`authenticate_bearer_with_confirmation` and `inject_http_auth_with_confirmation`;
when material is presented a token carrying `cnf` is always checked. Plain
validator paths fail closed under `require_cnf`.

### AUTH-25 (#34, purpose-token half): purpose tokens had no `jti`

Purpose tokens carry a random UUID `jti` (`IssuedPurposeToken::token_id`,
`VerifiedPurposeToken::token_id`). `jti` and `nbf` are reserved custom-claim
names. New `PurposeTokenReplayStore` trait and
`AuthService::consume_purpose_token(token, expected, &store)`: validates, then
consumes the `jti` atomically; a replay returns the new
`AuthError::PurposeTokenReplayed` (`PURPOSE_TOKEN_REPLAYED`); store errors fail
closed; a token without `jti` (minted by 0.26) validates with
`token_id = None` but cannot be consumed. Replay properties are documented. The
`step_up_session` empty-methods half was left to its stream.

### #38 (this stream's items)

- One HS256 minimum-length helper (`keys::validate_hs256_secret`) used by
  `StaticHs256Key`, the validator and `JwtKeyMaterial`.
- One `dedupe_stable` (`util.rs`, the `BTreeSet` version) replacing the copies
  in `grant.rs`, `token_decode.rs` and `service.rs`.
- `AuthConfig::validate` rejects `access_token_ttl > max_access_token_ttl`.
- `AuthPrincipal::expires_at()` returns the user's access-token expiry.

## Changelog

### Security

- `AuthError`'s `Display` is the safe public message; internal detail reaches
  logs only through `diagnostic()`, `internal_detail()` or `Debug`.
- Default user and principal guards refuse session-bound delegations and
  tokens with an `actor` claim unless the guard calls `allow_delegated()`.
- `ClaimRequirements::require_cnf` verifies the presented certificate or key
  thumbprint in constant time instead of only checking that `cnf` exists.
- HMAC algorithms are refused without `accept_hs256(true)` on every validator
  path, including custom key resolvers and HS384/HS512.
- Access-token validation requires `typ` and `purpose`, the `Bearer` scheme
  (validator) and the standard `scope` claim by default.
- A trailing scope wildcard matches whole segments only (`tenant.1*` no longer
  covers `tenant.10.read`).
- Guards and `has_all_scopes` helpers deny an empty requirement list.
- A JWKS key verifies only its own algorithm; `oct` keys, duplicate `kid`s and
  unidentified keys in multi-key documents are refused.
- Purpose tokens carry a `jti` and can be consumed once.

### Fixed

- `KeyRefreshPolicy::default()` matches the docs (`UseStale`, bounded), so the
  documented rotating-JWKS setup no longer fails every token after 5 minutes.
- Static JWKS: one-key documents with a `kid` require it; multi-key documents
  no longer require `key_id`; each key keeps its algorithm.
- Key-refresh durations saturate instead of wrapping.
- `AuthPrincipal::expires_at()` returns the user's access-token expiry.
- `access_token_ttl` may not exceed `max_access_token_ttl`.
- `internal_detail()` covers `InvalidOidcAuthorizationOptions`.
- Catalogue `exact_only` flags and patterns can now be enforced.

### Added

- `AuthError::diagnostic()` / `AuthErrorDiagnostic`.
- `AuthConfig::previous_verification_keys`, `with_previous_verification_key`,
  `JwtVerificationKey`, `MAX_PREVIOUS_VERIFICATION_KEYS`; `jwks()` publishes them.
- `AccessTokenValidatorBuilder::key_ids`.
- `KeyRefreshPolicy::max_stale`, `RotatingJwksKeySet::needs_refresh`.
- `PresentedConfirmation`, `AccessTokenMetadata::verify_confirmation`,
  `AccessTokenMetadata::is_delegated`,
  `ClaimRequirements::validate_with_confirmation`,
  `ClaimRequirementError::{ConfirmationMismatch, ConfirmationNotPresented}`.
- `AccessTokenValidator::{authenticate_access_token_with_confirmation,
  authenticate_bearer_with_confirmation, inject_http_auth_with_confirmation}`.
- `allow_delegated()` on every user and principal guard.
- `RoleScopeCatalogue::{hierarchical_scope_match, apply_exact_only}`.
- `PurposeTokenReplayStore`, `AuthService::consume_purpose_token`,
  `IssuedPurposeToken::token_id`, `VerifiedPurposeToken::token_id`,
  `AuthError::PurposeTokenReplayed` (`PURPOSE_TOKEN_REPLAYED`).
- Golden vectors version `2.0` (vectors 40 to 46).

### Breaking

- `Display` of `AuthError` changed for every variant whose old text differed
  from `public_message()`.
- `PurposePolicy`, `BearerParseMode` and `LegacyScopeClaims` defaults changed;
  `AuthConfig::new` / `with_hs256_secret` / `with_rs256_pem` default to
  `LegacyScopeClaims::Reject`; the service requires `typ` and `purpose`.
- Default guards refuse delegated/actor tokens; empty-list guards deny;
  `has_all_scopes(.., &[])` is `false`.
- `require_cnf` fails closed without presented material.
- Scope wildcard semantics (golden vector 8).
- Stricter JWKS parsing; one-key JWKS with `kid` requires the token `kid`; key
  algorithm must equal the header `alg`.
- `KeyRefreshPolicy` has a new public field; default stale policy changed.
- `AuthConfig`, `IssuedPurposeToken`, `VerifiedPurposeToken` have new public
  fields; `RequireAuth` and `RequirePrincipal` are no longer unit structs.
- New enum variants: `AuthError::PurposeTokenReplayed`,
  `ClaimRequirementError::{ConfirmationMismatch, ConfirmationNotPresented}`.
- `jti` and `nbf` are reserved purpose-token custom-claim names.
- `access_token_ttl > max_access_token_ttl` is a configuration error.

## Migration notes for host applications

**Error text.** Code that logged `err.to_string()` / `{err}` for diagnostics
must use `err.diagnostic()` (or `{err:?}`); the diagnostic text is unchanged
there. Tests asserting `AuthError` `Display` strings must assert the public
message or `public_code()`. Prefer `.extend()` over a plain `?` in resolvers to
send `extensions.code`.

**Validation defaults (rolling upgrade).** A 0.26 issuer mints tokens that pass
the new defaults, so resource servers and issuers can upgrade in either order,
provided that:

1. Every client sends `Authorization: Bearer <token>`, including WebSocket
   `connection_init` values read by `AccessTokenValidator`. Otherwise set
   `.bearer_parse_mode(BearerParseMode::BearerOrRaw)`.
2. No issuer uses `AccessTokenScopeClaimFormat::LegacyArray`. If one does,
   switch it to `Standard` and wait the maximum access-token TTL, or set
   `.legacy_scope_claims(LegacyScopeClaims::Accept)` on validators and
   `.with_legacy_scope_claims(LegacyScopeClaims::Accept)` on that issuer's
   `AuthConfig` (`AuthService::new` now refuses `LegacyArray` without it).
3. No pre-0.6 issuer is still running. If one is, set
   `.purpose_policy(PurposePolicy::AccessTokenOrLegacy)` on validators.

Code relying on `PurposePolicy::default()`, `BearerParseMode::default()` or
`LegacyScopeClaims::default()` gets the strict variant.

**Guards.** Resolvers that must run for session-bound delegations, actor
(impersonation / on-behalf-of) tokens or sessionless grants with `actor` add
`.allow_delegated()` to their guard. Code naming `RequireAuth` or
`RequirePrincipal` as a unit value (`guard = "RequireAuth"`) must call
`RequireAuth::new()`. A guard built from a possibly empty list now denies; build
it only with a non-empty list.

**`cnf`.** Resource servers using `require_cnf` / `tenant_jti_and_cnf()` must
pass the verified certificate or JWK thumbprint through
`authenticate_bearer_with_confirmation` or `inject_http_auth_with_confirmation`.
`ClaimRequirements::validate` callers with `require_cnf` switch to
`validate_with_confirmation`. Exhaustive matches on `ClaimRequirementError`
need the two new variants.

**Scopes.** Grants such as `orders*` or `tenant.1*` that relied on a raw prefix
must become segment wildcards (`orders.*`, `tenant.1.*`). Routers implementing
`scope_match_golden.json` must adopt version `2.0`. Hosts that verified a
role-scope catalogue should build their matcher with
`catalogue.hierarchical_scope_match(options)` to enforce `exact_only`.

**JWKS / keys.** Static JWKS documents must give every key in a multi-key
document a unique `kid` and contain no `oct` keys; non-RS256 keys need
`allowed_algorithms`. Tokens validated against a one-key JWKS whose key has a
`kid` must carry it. `KeyRefreshPolicy { .. }` struct literals add `max_stale`
(or use `..KeyRefreshPolicy::default()`). Hosts using `RotatingJwksKeySet` must
refresh periodically (`needs_refresh()`); keys stop verifying after
`cache_ttl + max_stale` without a successful refresh. A custom `key_resolver`
returning HMAC keys needs `accept_hs256(true)`.

**Config.** `AuthConfig { .. }` struct literals add
`previous_verification_keys: Vec::new()`. Configurations with
`access_token_ttl > max_access_token_ttl` must raise the maximum or lower the
TTL.

**Purpose tokens.** `IssuedPurposeToken` / `VerifiedPurposeToken` literals add
`token_id`. Custom claims named `jti` or `nbf` are refused. Purpose tokens
minted by a 0.26 node during a rolling upgrade still validate but cannot be
consumed. Exhaustive matches on `AuthError` add `PurposeTokenReplayed`.
`PurposeTokenReplayStore` implementors must insert atomically and keep ids
until `expires_at`.

## Tests

New files: `src/tests/{error_display, key_rotation, validation_defaults,
guard_edges, confirmation, purpose_token_replay, token_config}.rs`, plus
`role_scope::tests::catalogue_exact_only_flags_are_enforced_by_its_matcher`.
21 of the tests written against the pre-fix API failed on unfixed code (output
kept in the stream's scratch log); tests for new APIs could not compile before
the fix. Four pinned already-correct behaviour and passed before:
`current_issuer_tokens_pass_the_strict_defaults`,
`key_resolver_switching_to_hmac_at_request_time_is_refused`,
`plain_purpose_token_validation_is_repeatable`,
`hs256_minimum_secret_length_is_enforced_on_every_path`.

Existing tests changed deliberately because they pinned the old behaviour:
`claims_and_status::claim_requirements_require_tenant_jti_and_cnf` (presence
no longer suffices), `grant::session_bound_grant_preserves_...` (its
`require_cnf` validator now uses the confirmation path),
`jwt_signing::legacy_access_tokens_without_purpose_still_decode` (renamed to
`..._without_typ_and_purpose_are_rejected`),
`validator::validator_accepts_legacy_access_tokens_without_purpose` (now
`..._only_when_opted_in`), `validator::validator_injects_auth_runtime_...` (raw
value now `InvalidBearerToken`), `time_invariants::service_rejects_invalid_...`
(TTL bound), `scopes::*` (legacy acceptance made explicit),
`scope_match` vector 8. Fixtures that carried an incidental legacy
`"scopes": []` claim (claims_and_status, validator) now use the standard claim
or none.
