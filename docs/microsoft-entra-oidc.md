# Microsoft Entra OIDC

`agql-auth` supports Microsoft Entra ID login using the OIDC/OAuth2
authorization-code flow with PKCE. Microsoft tokens verify the login event; they
do not become the application's long-lived session tokens. After validation and
host-controlled user resolution, `agql-auth` issues a normal local
`AuthPayload`.

## Microsoft App Registration

In Microsoft Entra admin center:

1. Create or select an app registration.
2. Add a web redirect URI, for example
   `https://app.example.com/auth/microsoft/callback`.
3. Record the application client ID.
4. Create a client secret for confidential web clients.
5. Ensure the app can request `openid profile email`.
6. Request `offline_access` only if the host will explicitly store provider
   refresh tokens with encrypted storage.

## Tenant Modes

Use one of the `MicrosoftEntraConfig` constructors:

```rust
use agql_auth::MicrosoftEntraConfig;

let single = MicrosoftEntraConfig::single_tenant(
    "00000000-0000-0000-0000-000000000000",
    client_id,
    redirect_uri,
);

let organizations = MicrosoftEntraConfig::organizations(client_id, redirect_uri);
let common = MicrosoftEntraConfig::common(client_id, redirect_uri);
let consumers = MicrosoftEntraConfig::consumers(client_id, redirect_uri);
```

`consumers` is disabled by default unless that constructor is used. For
multi-tenant work/school logins, set `allowed_tenants` when only specific
tenants should be accepted.

## Provider Setup

The host supplies an HTTP client implementing `OidcHttpClient`; this keeps the
crate independent of `reqwest`, `axum`, `actix-web`, or any other transport.

```rust
use std::sync::Arc;

use agql_auth::{MicrosoftEntraConfig, OidcProvider};

let mut config = MicrosoftEntraConfig::single_tenant(
    "00000000-0000-0000-0000-000000000000",
    std::env::var("MICROSOFT_CLIENT_ID")?,
    "https://app.example.com/auth/microsoft/callback",
);
config.client_secret = Some(std::env::var("MICROSOFT_CLIENT_SECRET")?);

let microsoft = OidcProvider::new(
    config.into_oidc_provider_config()?,
    Arc::new(app_oidc_http_client),
)?;
```

The generated authorization URL includes:

- `client_id`
- `redirect_uri`
- `response_type=code`
- `response_mode=query`
- `scope=openid profile email`
- optional `offline_access`
- `state`
- `nonce`
- `code_challenge`
- `code_challenge_method=S256`

## Start Route

The host owns the route and redirect response:

```rust
async fn microsoft_start(state: AppState) -> Result<(CookieJar, Redirect), AppError> {
    let request = state
        .microsoft
        .create_authorization_request(&state.oauth_state_store)
        .await?;

    // Bind the flow to this browser (login CSRF protection).
    let binding = request.browser_binding.expect("browser binding is required by default");
    let cookie = Cookie::build(("__Host-oidc_binding", binding))
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::minutes(10)); // at most state_ttl

    Ok((CookieJar::new().add(cookie), Redirect::to(&request.authorization_url)))
}
```

`create_authorization_request` stores hashed state, nonce, PKCE verifier and
the hash of a random browser-binding secret through `OAuthStateStore`, and
returns the raw secret in `request.browser_binding`. The PKCE verifier is not
returned. The store must persist every field, consume state exactly once during
the callback and return the pre-consumption snapshot. A callback using an
already consumed state is rejected.

### Browser binding

Set `request.browser_binding` as a cookie before redirecting, and read it back
at the callback:

- `HttpOnly` and `Secure`, ideally with the `__Host-` prefix and `Path=/`.
- `SameSite=Lax` for the default query response mode: the provider's redirect
  is a top-level `GET`, which carries `Lax` cookies.
- `Max-Age` no longer than `state_ttl`; clear it after the callback.
- With `response_mode=form_post` the provider `POST`s cross-site, and a `Lax`
  or `Strict` cookie is not sent. Use `SameSite=None; Secure` for this cookie,
  or bind the flow another way (see
  [form_post](oidc-form-post-and-client-credentials.md#browser-binding-for-form_post)).
- One cookie per provider name; a second login started in another tab replaces
  it and fails the first flow closed.

A callback without the value, or with a different one, fails with
`InvalidOAuthState` (`INVALID_OAUTH_STATE`) after its state is consumed. Hosts
that already bind `state` to the browser themselves can set
`OidcProviderConfig::browser_binding = OAuthBrowserBinding::NotRequiredHostBindsState`;
states created that way carry no hash, and states without a hash are refused
while binding is required.

## Callback Route

The callback should pass only the authorization code, state and `iss` from the
query string, plus the binding cookie. Do not accept frontend-provided ID tokens
or provider access tokens as proof of login.

```rust
use agql_auth::{ClientMetadata, OidcCallbackInput};

async fn microsoft_callback(
    state: AppState,
    query: MicrosoftCallbackQuery,
) -> Result<AuthResponse, AppError> {
    let result = state
        .microsoft
        .login_with_callback(
            &state.auth,
            &state.oauth_state_store,
            &state.external_identity_store,
            &state.external_user_provisioner,
            &state.claims_mapper,
            OidcCallbackInput {
                code: query.code,
                state: query.state,
                iss: query.iss,
                browser_binding: cookies.get("__Host-oidc_binding").map(|c| c.value().to_string()),
                error: query.error,
                error_description: None,
            },
            ClientMetadata {
                ip_address: query.ip_address,
                user_agent: query.user_agent,
            },
        )
        .await?;

    Ok(AuthResponse::from_auth_payload(result.auth))
}
```

`login_with_callback` performs discovery, state validation, browser-binding
and `iss` checks, token exchange, JWKS lookup, ID-token validation, nonce
validation, tenant validation, external identity lookup, claims mapping,
provisioning, a local account check, identity linking, and local session
issuance.

Register one redirect URI per provider and route it to that provider only. With
a shared callback URL a response could be handed to the wrong provider.
When the callback carries the RFC 9207 `iss` parameter, it must match the
provider issuer before the code is exchanged; for `organizations` and `common`
it must match the `{tenantid}` template and then equal the ID token `iss`. When
the discovery document sets `authorization_response_iss_parameter_supported`, a
callback without `iss` is refused.

## User Provisioning

The host implements `ExternalUserProvisioner` to decide what a validated
external identity means locally:

- create a new local user
- link to an existing local user
- reject the login
- assign local roles
- assign local scopes

The provisioner receives validated claims, any existing external identity, and
the output from the claims mapper. After it returns, `login_with_callback`
re-reads that user from the `AuthService` user store: a disabled user fails with
`UserDisabled` (`USER_DISABLED`) and a missing user with
`ExternalLoginRejected` (`FORBIDDEN`), before any identity is linked or updated
and before a session is issued. The provisioner remains responsible for any
other account policy.

## Claims Mapping

Use `MicrosoftClaimsMapper` for simple mappings from Microsoft claims to local
roles and scopes:

```rust
use agql_auth::MicrosoftClaimsMapper;

let mapper = MicrosoftClaimsMapper::new()
    .map_role_to_role("App.Admin", "Admin")
    .map_role_to_scope("App.Admin", "admin")
    .map_group_to_scope("00000000-0000-0000-0000-000000000001", "billing.read");
```

For custom policy, implement `ClaimsMapper` directly.

Validated standard `auth_time`, `amr`, and `acr` values are available on
`ValidatedOidcClaims`, but they are evidence rather than local authorization.
Provider-returned `acrs` is exposed as a separate bounded string list and is
never merged with standard scalar `acr`.
Neither `MicrosoftClaimsMapper` nor `NoopClaimsMapper` treats any provider value
as MFA. A custom mapper may return `MappedClaims.assurance` only after explicit
host policy accepts the provider's methods/ACR. Do not assume a Microsoft (or
other provider) claim value universally means MFA. See
[session assurance](session-assurance.md).

For recent active authentication, use the typed bound authorization API in
[OIDC reauthentication and step-up](oidc-step-up.md). `prompt=login` and
`max_age` do not prove MFA. When deterministic Conditional Access
authentication-context step-up is required, use
`OidcIdTokenClaimRequest::EssentialAcrs { value }` for the exact configured
context; do not substitute scalar `acr_values` or `EssentialAcr`. Entra
authentication-context/optional-claim behavior must be configured and verified
for the exact tenant, application, and token type. A successful bound match is
provider evidence only; the host must separately allowlist/map it and no
context identifier universally means MFA.

Do not use email, UPN, name, or preferred username as authorization
identifiers. For Microsoft work/school accounts, the preferred stable external
identity key is `tid + oid`; generic OIDC falls back to `iss + sub`.

## Validation Rules

Microsoft ID-token validation covers:

- signature
- allowed algorithm
- `kid`
- issuer
- audience
- expiry
- not-before, when the provider supplies `nbf`
- issued-at
- the signing key's JWKS `issuer` metadata, when present: the token `iss` must
  equal it with `{tenantid}` replaced by the token `tid` (Microsoft's
  multi-tenant guidance; keys without `issuer` metadata rely on the issuer
  template check alone)
- nonce
- tenant ID
- object ID or subject-derived fallback
- `azp` for multi-audience tokens

Consumer accounts are rejected unless explicitly enabled. Disallowed tenants,
unknown key IDs, invalid nonce, invalid issuer, invalid audience, expired
tokens, and replayed states are rejected.

For generic OIDC providers, `nbf` is optional. If present, it is validated with
the configured clock skew. `exp`, `nbf`, `iat` and `auth_time` are compared with
the provider's clock (`OidcProvider::new_with_clock`; the system clock by
default).

## Discovery

`discovery_url` must be `https://` (`http://` only for loopback hosts). The
discovery document's `issuer` must equal the expected issuer exactly
(OIDC Discovery section 4.3): `MicrosoftEntraConfig` sets it to
`https://login.microsoftonline.com/{tenant}/v2.0` for a tenant, the literal
`https://login.microsoftonline.com/{tenantid}/v2.0` template for
`organizations` and `common`, and the consumer tenant's issuer for `consumers`.
Every discovered endpoint (authorization, token, JWKS and, when present,
userinfo) must be `https://` as well. A failing document is
`OidcDiscovery` (`AUTH_SERVICE_UNAVAILABLE`) and is not cached.

`allowed_id_token_algs` must name algorithms of one key family (Entra uses
`RS256`); `HS*` is refused at configuration time. `redirect_uri` must be an
absolute `https://` URL without a fragment, and `state_ttl` at most one hour. If an ID token has multiple audiences, `azp` must be
present and equal to the configured `client_id`; additional audiences must be
listed in `allowed_additional_audiences`.

## Cache And Audience Controls

`OidcProviderConfig` and `MicrosoftEntraConfig` include:

- `jwks_cache_ttl`
- `discovery_cache_ttl`
- `jwks_forced_refresh_cooldown`
- `allowed_additional_audiences`
- `clock_skew`

Unknown `kid` values can trigger one forced JWKS refresh, but repeated unknown
keys are throttled by `jwks_forced_refresh_cooldown` to avoid hammering the
identity provider. Set the cooldown to zero only in tests or when another layer
already rate-limits callbacks.

## Current authority for sensitive operations

See [principal lifecycle](principal-lifecycle.md#current-authority-for-sensitive-operations)
for immediate fail-closed status/current-grant checks and the
[0.20 migration](../MIGRATION.md#0192-to-0200-current-authority-and-sensitive-operations)
for refresh provenance, stored role ceilings, and mandatory host/OIDC authority.
