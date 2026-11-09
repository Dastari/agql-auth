# Release notes: OIDC and OAuth 2.0 client (stream `oidc`)

Scope: `OidcProvider`, `OAuth2Provider`, token-endpoint client authentication,
OIDC/OAuth 2.0 configuration and models, and their docs.

## Findings

### AUTH-5 (medium): external login ignored the local disabled flag

`OidcProvider::login_with_callback*` issued a session for whatever user the
host provisioner returned, and the provisioner contract never mentioned
`disabled`. The login now re-reads the provisioned user from the
`AuthService`'s `UserStore` after provisioning and before any identity is
linked or updated: a disabled user fails with `UserDisabled` (`USER_DISABLED`,
as for password login and refresh), a missing user with
`ExternalLoginRejected` (`FORBIDDEN`), and a store returning another ID with
`AuthServiceUnavailable`. `OAuth2Provider` had no session-issuing path; its
documented integration stopped at the profile and left the host to call
`issue_verified_user_session*`, which does not load the user. It gains
`OAuth2Provider::login_with_callback` with an `OAuth2UserProvisioner` trait,
the same account check, identity linking and a session with the new
`AuthMethod::OAuth2`. The `ExternalUserProvisioner` contract and the docs now
state the check. Tests: `oidc_hardening::oidc_login_refuses_a_disabled_local_user`,
`oidc_hardening::oidc_login_refuses_a_missing_local_user` (both failed before
the fix), `oauth_callback_binding::oauth2_login_with_callback_enforces_local_account_state_and_issues_a_session`.

### AUTH-10 (low): discovery URL, endpoints and issuer not validated

`OidcProviderConfig::validate` now requires `discovery_url` to be `https://`
(`http://` only for loopback), using the rule `OAuth2ProviderConfig` already
applied. `discover()` refuses, without caching, a document whose
authorization, token, JWKS or (when present) userinfo endpoint is not
`https://`, and one whose `issuer` differs from the expected issuer (OIDC
Discovery section 4.3). The expected issuer is the new
`OidcProviderConfig::issuer` when set (compared exactly), otherwise it is
derived from a `.../.well-known/openid-configuration` discovery URL (the prefix,
with or without one trailing `/`, the only two issuers that produce that URL);
a non-standard discovery URL without `issuer` is a configuration error.
`MicrosoftEntraConfig` sets the issuer explicitly: the tenant issuer, the
literal `https://login.microsoftonline.com/{tenantid}/v2.0` template for
`organizations`/`common` (substituted only during ID-token validation), and
the consumer tenant issuer for `consumers`. Hand-built Entra configs with
those discovery URLs derive the same values. Tests:
`oidc_configuration_requires_https_discovery_and_redirect_uri`,
`oidc_discovery_refuses_insecure_endpoints`,
`oidc_discovery_requires_the_configured_issuer_exactly` (all failed before).

### AUTH-11 (low): Entra ignored the JWKS per-key issuer

The JWKS cache now keeps each key's `issuer` metadata (first key per `kid`,
matching `JwkSet::find`). For `OidcProviderKind::MicrosoftEntra`, when the
signing key has `issuer`, the token `iss` must equal it with `{tenantid}`
replaced by the token `tid`, as Microsoft's multi-tenant guidance and
`Microsoft.IdentityModel` do; keys without the metadata keep only the existing
issuer-template check. Generic providers are unchanged (the member is not
standard). Test: `entra_multi_tenant_validates_the_signing_key_issuer` (failed
before: a key scoped to another tenant was accepted).

### AUTH-12 (low): OAuth state not bound to the initiating browser

Both providers now issue a browser-binding secret by default. The
authorization request returns `browser_binding` (48 random bytes, base64url);
only its SHA-256 hex is stored in the new `OAuthLoginState::browser_binding_hash`.
The host sets it as a cookie and passes it back in the new
`OidcCallbackInput::browser_binding`; the callback compares hashes in constant
time after consuming the state. A missing or wrong value, or a state without a
hash while binding is required (for example a pre-upgrade state), fails with
`InvalidOAuthState` (`INVALID_OAUTH_STATE`), and the state stays consumed. The
explicit opt-out is `OAuthBrowserBinding::NotRequiredHostBindsState` on
`OidcProviderConfig::browser_binding` / `OAuth2ProviderConfig::browser_binding`
for hosts that bind state themselves; a bound state still requires its value
after opting out. Docs give the cookie step (`__Host-`, `HttpOnly`, `Secure`,
`SameSite=Lax` for query, `Max-Age` at most `state_ttl`) and the `form_post`
caveat (`SameSite=None; Secure`, or a same-site handoff). Tests:
`oidc_callback_requires_the_initiating_browser_binding`,
`browser_binding_opt_out_is_explicit_and_legacy_states_fail_closed`,
`oauth2_callback_requires_the_initiating_browser_binding` (new API; they do not
compile against 0.26.0, which had no binding to check).

### AUTHX-7 / #40 (low): OAuth 2.0 / OIDC client hardening

1. **RFC 9207.** `OidcCallbackInput` gains `iss` (`with_issuer`). OIDC: when
   present, or when discovery sets `authorization_response_iss_parameter_supported`,
   it must match the provider issuer before the code is exchanged (for the Entra
   template, `{tenantid}` matches one path segment) and must then equal the
   validated ID token `iss`; failures are `OidcCallback` (`UNAUTHENTICATED`).
   OAuth 2.0: new `OAuth2ProviderConfig::issuer` and
   `require_authorization_response_iss`; an `iss` must equal `issuer`, and an
   `iss` with no configured issuer is refused (`OAuthCallback`). Docs make one
   redirect URI per provider mandatory. Tests:
   `oidc_authorization_response_iss_is_checked_before_code_exchange`,
   `entra_multi_tenant_response_iss_must_match_the_id_token_tenant`,
   `oauth2_authorization_response_iss_requires_a_configured_issuer`.
2. **Visibility.** `OidcProvider::exchange_code`, `OAuth2Provider::exchange_code`
   and `OAuth2Provider::fetch_profile` are now `pub(crate)`: no public API turns
   a client-supplied access token into an identity. (Compile-time; no runtime
   test.)
3. **`private_key_jwt`.** The assertion `aud` defaults to the issuer identifier:
   the validated discovery `issuer` for generic OIDC, `OAuth2ProviderConfig::issuer`
   when set. Microsoft Entra keeps the token endpoint (Microsoft's documented
   assertion format) and an `OAuth2Provider` without `issuer` keeps its
   configured token endpoint (no discovery, so the audience-injection case does
   not arise). `iss` and `sub` must equal `client_id`, and the lifetime is at
   most `MAX_PRIVATE_KEY_JWT_LIFETIME_SECONDS` (600). Signed client secrets
   (Sign in with Apple) keep their own issuer, the token-endpoint default and
   the six-month maximum. `ClientJwtClaims` gains optional `x5t#S256`
   (`with_x509_sha256_thumbprint`, validated as a 32-byte base64url digest) and
   `nbf = iat` (`with_not_before`). Tests:
   `private_key_jwt_audience_defaults_to_the_issuer`,
   `private_key_jwt_requires_client_id_issuer_subject_and_a_short_lifetime`
   (both failed before), `client_assertion_carries_optional_x5t_s256_and_nbf`.
4. **Redirects.** `OidcHttpClient` docs require that redirects are not followed
   (any 3xx is `Err`).
5. **Bounds.** Negative `expires_in` fails the exchange (`OidcTokenExchange` /
   `OAuthTokenExchange`). `redirect_uri` must be an absolute `https://` URL
   without a fragment (`http://` on loopback) for both providers. `state_ttl`
   is at most `MAX_OAUTH_STATE_TTL_SECONDS` (3600). Profile `email`, `name` and
   `picture` (OAuth 2.0) and ID-token `email`, `name`, `preferred_username`
   longer than `MAX_OAUTH2_EMAIL_LENGTH` (320) / `MAX_OAUTH2_NAME_LENGTH` (512) /
   `MAX_OAUTH2_PICTURE_LENGTH` (2048) bytes are treated as absent (an over-long
   OAuth 2.0 email also clears `email_verified`). Tests:
   `negative_expires_in_is_refused_by_both_providers`,
   `oauth2_redirect_uri_must_be_an_absolute_https_url`,
   `state_ttl_is_bounded_for_both_providers`,
   `oauth2_profile_values_are_length_bounded` (all failed before).
6. **Zeroization.** `client_secret` in `OidcProviderConfig`,
   `OAuth2ProviderConfig` and `MicrosoftEntraConfig` is overwritten on drop;
   token-request forms and headers (secret, Basic credentials, assertion, code,
   verifier) and bearer headers are overwritten after each request;
   `OidcTokenResponse` and `OAuth2TokenResponse` overwrite their tokens and
   every string of `raw` on drop; the password copies handed to the Argon2
   worker are `Zeroizing`. Best effort: host copies and earlier reallocations
   are not covered. `OAuth2AuthorizationRequest::code_verifier` is removed, and
   so is the sibling `OidcAuthorizationRequest::code_verifier`; the verifier
   lives only in the stored state.

### #38 (bullets in scope)

- **`allowed_id_token_algs`.** Validated at configuration time: every entry
  must parse, all must share one key family (RSA `RS*`/`PS*`, EC
  `ES256`/`ES384`, or `EdDSA`), and symmetric `HS*` is refused (ID tokens are
  verified against JWKS public keys only). Test:
  `allowed_id_token_algorithms_must_share_one_key_family` (failed before).
- **OIDC clock.** `exp` and `nbf` were checked by `jsonwebtoken` against the
  system clock while `iat`/`auth_time` used the injected clock. They are now
  checked against the provider's injected clock with `clock_skew`. Test:
  `id_token_time_checks_use_the_provider_clock` (confirmed failing with the old
  system-clock validation restored).

## Changelog

### Security

- OIDC and OAuth 2.0 logins refuse disabled (`USER_DISABLED`) and missing
  (`FORBIDDEN`) local users before linking identities or issuing a session.
- OAuth state is bound to the initiating browser by default (login CSRF);
  callbacks need the `browser_binding` cookie value.
- OIDC discovery requires `https` for the discovery URL and every discovered
  endpoint, and an exact issuer match.
- Microsoft Entra ID tokens must match the signing key's JWKS `issuer`
  metadata, with `{tenantid}` substituted by `tid`.
- RFC 9207 `iss` authorization-response checks for both providers.
- `private_key_jwt` assertions default `aud` to the issuer identifier, require
  `iss == sub == client_id` and live at most ten minutes.
- `exchange_code` and `fetch_profile` are no longer public.
- Client secrets, request credentials, provider tokens and password copies are
  zeroized on drop or after use.

### Fixed

- `allowed_id_token_algs` mixing key families (or naming `HS*`/unknown
  algorithms) is a configuration error instead of failing every login.
- ID-token `exp`/`nbf` use the provider's injected clock.
- Negative `expires_in` is refused; `redirect_uri` must be an absolute
  `https` URL; `state_ttl` is capped at one hour; profile and ID-token
  email/name/picture values are length-bounded.

### Added

- `OAuth2Provider::login_with_callback`, `OAuth2UserProvisioner`,
  `OAuth2LoginResult`, `AuthMethod::OAuth2`.
- `OAuthBrowserBinding` (`Required`, `NotRequiredHostBindsState`);
  `browser_binding` on both provider configs and authorization requests;
  `OidcCallbackInput::{iss, browser_binding}`, `with_issuer`,
  `with_browser_binding`; `OAuthLoginState::browser_binding_hash`.
- `OidcProviderConfig::issuer`; `OAuth2ProviderConfig::{issuer,
  require_authorization_response_iss}`.
- `ClientJwtClaims::{x509_sha256_thumbprint, include_not_before}`,
  `with_x509_sha256_thumbprint`, `with_not_before`.
- Constants `MAX_OAUTH_STATE_TTL_SECONDS`, `MAX_PRIVATE_KEY_JWT_LIFETIME_SECONDS`,
  `MAX_OAUTH2_EMAIL_LENGTH`, `MAX_OAUTH2_NAME_LENGTH`, `MAX_OAUTH2_PICTURE_LENGTH`.
- Direct dependency on `zeroize` 1 (already in the lock graph via
  `jsonwebtoken`'s RSA/EC crates; no new crate is downloaded).

### Breaking

- Browser binding is required by default; callbacks without the value fail.
- `OidcAuthorizationRequest::code_verifier` and
  `OAuth2AuthorizationRequest::code_verifier` are removed.
- `OidcProvider::exchange_code`, `OAuth2Provider::exchange_code` and
  `OAuth2Provider::fetch_profile` are crate-private.
- New fields on `OidcProviderConfig`, `OidcCallbackInput`, `OAuthLoginState`
  and `OidcAuthorizationRequest` (struct literals); new `AuthMethod::OAuth2`
  variant (exhaustive matches).
- `OidcProviderConfig`, `OAuth2ProviderConfig`, `MicrosoftEntraConfig`,
  `OidcTokenResponse` and `OAuth2TokenResponse` implement `Drop`: fields can
  no longer be moved out of them.
- Stricter configuration: https discovery URL, absolute https `redirect_uri`,
  `state_ttl` at most one hour, one key family in `allowed_id_token_algs`,
  `private_key_jwt` `iss`/`sub`/lifetime rules, `issuer` required for a
  non-standard discovery URL.
- Generic-OIDC `private_key_jwt` assertions use the issuer as `aud` instead of
  the token endpoint.
- OIDC logins fail for provisioned users absent from the `UserStore`.

## Migration notes for host applications

**Browser binding (all OIDC/OAuth 2.0 hosts).** At the start route, store
`request.browser_binding` (an `Option<String>`, `Some` by default) in a cookie:
`__Host-<provider>_binding`, `Path=/`, `Secure`, `HttpOnly`, `SameSite=Lax`
(query mode), `Max-Age` at most `state_ttl`. At the callback, read it into
`OidcCallbackInput::browser_binding` (or `.with_browser_binding(value)`), then
clear the cookie. For `form_post` use `SameSite=None; Secure; HttpOnly` or a
same-site `GET` handoff. Hosts that already bind state themselves set
`config.browser_binding = OAuthBrowserBinding::NotRequiredHostBindsState`.
Flows in flight during the upgrade fail with `INVALID_OAUTH_STATE` and must be
restarted (states live at most `state_ttl`).

**Store implementors (`OAuthStateStore`).** Persist and return the new
nullable `browser_binding_hash` column (64 hex characters) unchanged; add it to
the `RETURNING` list of `consume_oauth_state`. Serialized records omit it when
`None` and deserialize without it. A store that drops it makes every bound
callback fail closed.

**Struct literals.** `OidcCallbackInput { .. }` needs `iss` and
`browser_binding` (both `Option<String>`; `serde(default)` for JSON input).
`OAuthLoginState { .. }` needs `browser_binding_hash`. `OidcProviderConfig { .. }`
needs `issuer` and `browser_binding` (prefer `OidcProviderConfig::new`).
`OidcAuthorizationRequest { .. }` loses `code_verifier`, gains
`browser_binding`. `OAuth2ProviderConfig` and `ClientJwtClaims` are
`non_exhaustive` and take the new fields with defaults.

**Removed `code_verifier`.** Read it from the stored `OAuthLoginState` if
needed; never send it to the browser.

**`exchange_code` / `fetch_profile`.** Use `handle_callback` or
`login_with_callback`. A host that resolved identity from a client-supplied
access token must stop: such a token carries no audience proof.

**OAuth 2.0 session issuance.** Replace `handle_callback` + host-issued session
with `OAuth2Provider::login_with_callback(auth, state_store, identity_store,
&provisioner, input, metadata)` and implement `OAuth2UserProvisioner`. Hosts
keeping `handle_callback` must load the user and refuse `disabled` before
calling `issue_verified_user_session*`.

**OIDC provisioners.** The returned `user_id` must exist in the `AuthService`
`UserStore`; create it before returning. Disabled users now fail with
`USER_DISABLED`, missing ones with `FORBIDDEN`.

**Exhaustive matches.** Add an arm for `AuthMethod::OAuth2`. Validators built
from older versions cannot deserialize sessions with this method; upgrade
resource servers before issuing OAuth 2.0 sessions.

**`Drop` types.** Code moving a field out of `OidcTokenResponse`,
`OAuth2TokenResponse` or a provider config (for example
`let token = response.access_token;`) must clone it or use
`std::mem::take(&mut response.access_token)`. Struct update syntax
`..config` from these types is no longer allowed.

**Configuration.**
- `discovery_url` and `redirect_uri` must be `https://` (loopback `http://`
  allowed); `redirect_uri` must not contain `#`.
- A discovery URL that does not end in `/.well-known/openid-configuration`
  needs `OidcProviderConfig::issuer`. If the provider's discovery `issuer`
  differs from the URL prefix (beyond one trailing `/`), set `issuer` to the
  exact advertised value.
- `state_ttl` above one hour fails validation.
- `allowed_id_token_algs` must use one key family and no `HS*`; split mixed
  lists (for example keep `RS256`/`PS256`, drop `ES256`) to the family the
  provider's JWKS uses.
- `private_key_jwt`: `ClientJwtClaims::new(client_id, client_id)` with a
  lifetime of at most ten minutes. Generic-OIDC providers that only accept the
  token endpoint as audience need `.with_audience(token_endpoint)`. An
  `OAuth2Provider` that sets `issuer` now uses it as the default audience.
- `OAuth2Provider` hosts whose provider returns `iss` must set `issuer`
  (and may set `require_authorization_response_iss`); otherwise callbacks
  carrying `iss` fail with `UNAUTHENTICATED`. Pass the callback `iss` through.

**Error codes.** No new codes. New failure paths map to `INVALID_OAUTH_STATE`
(binding), `UNAUTHENTICATED` (`OidcCallback` / `OAuthCallback` for `iss`),
`AUTH_SERVICE_UNAVAILABLE` (`OidcDiscovery` for issuer/scheme, token-exchange
`expires_in`), `USER_DISABLED` and `FORBIDDEN` (local account check),
`INVALID_CONFIGURATION` (new configuration rules).

**Wire formats.** `OAuthLoginState` JSON gains optional `browser_binding_hash`;
`OidcAuthorizationRequest` JSON drops `code_verifier` and gains optional
`browser_binding`; `OidcCallbackInput` JSON gains optional `iss` and
`browser_binding`; session context may carry `"auth_method": "OAuth2"`.

## Integration notes

- `src/service.rs`: `mod external_login;` plus two `Zeroizing` wraps in
  `hash_password_async` / `verify_password_async_before` (likely to touch the
  password-work stream's edits). The account check lives in
  `src/service/external_login.rs`.
- The disabled-user error is `UserDisabled`, matching the current password
  login and refresh. If another stream collapses password-login account-state
  errors (AUTH-9), decide whether external login should follow; this stream
  keeps the crate's existing public error.
- `src/session.rs`: new `AuthMethod::OAuth2` variant.
- `src/config.rs`: `OAuthBrowserBinding`, OIDC config fields and validation,
  `MicrosoftEntraConfig::into_oidc_provider_config` now takes `mut self`
  internally (same public signature).
- The ID-token `exp`/`nbf` checks now use the provider's injected clock; the
  clock-unification change should keep `OidcProvider` on its own clock.
- `Cargo.toml`/`Cargo.lock`: `zeroize = "1"` added as a direct dependency (one
  lock line); it was already resolved at 1.9.0 through `jsonwebtoken`'s
  crypto dependencies.
