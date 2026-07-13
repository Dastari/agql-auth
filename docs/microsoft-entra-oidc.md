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
async fn microsoft_start(state: AppState) -> Result<Redirect, AppError> {
    let request = state
        .microsoft
        .create_authorization_request(&state.oauth_state_store)
        .await?;

    Ok(Redirect::to(&request.authorization_url))
}
```

`create_authorization_request` stores hashed state, nonce, and PKCE verifier
through `OAuthStateStore`. The store must consume state exactly once during the
callback and return the pre-consumption snapshot. A callback using an already
consumed state is rejected.

## Callback Route

The callback should pass only the authorization code and state from the query
string. Do not accept frontend-provided ID tokens as proof of login.

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
            OidcCallbackInput::code_and_state(query.code, query.state),
            ClientMetadata {
                ip_address: query.ip_address,
                user_agent: query.user_agent,
            },
        )
        .await?;

    Ok(AuthResponse::from_auth_payload(result.auth))
}
```

`login_with_callback` performs discovery, token exchange, JWKS lookup, ID-token
validation, state validation, nonce validation, tenant validation, external
identity lookup/linking, claims mapping, and local session issuance.

## User Provisioning

The host implements `ExternalUserProvisioner` to decide what a validated
external identity means locally:

- create a new local user
- link to an existing local user
- reject the login
- assign local roles
- assign local scopes

The provisioner receives validated claims, any existing external identity, and
the output from the claims mapper.

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
`max_age` do not prove MFA. Entra authentication-context/optional-claim behavior
must be configured and verified for the exact tenant, application, and token
type; this crate does not assume that an ID token will contain `acrs` or that
any context identifier universally means MFA.

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
- nonce
- tenant ID
- object ID or subject-derived fallback
- `azp` for multi-audience tokens

Consumer accounts are rejected unless explicitly enabled. Disallowed tenants,
unknown key IDs, invalid nonce, invalid issuer, invalid audience, expired
tokens, and replayed states are rejected.

For generic OIDC providers, `nbf` is optional. If present, it is validated with
the configured clock skew. If an ID token has multiple audiences, `azp` must be
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
