# agql-auth

A reusable authentication library for `async-graphql` applications.

## Scope

This crate provides:

- Argon2 password hashing and verification
- short-lived JWT access tokens
- rotated opaque refresh tokens
- first-class string scope claims alongside roles
- structured session-context claims for auth method, MFA state, and active scope
- database-agnostic storage traits
- password-reset token issuance and verification primitives
- one-time login challenge and code primitives
- TOTP secret generation, provisioning, and verification primitives
- OpenID Connect authorization-code + PKCE login primitives
- Microsoft Entra ID provider configuration and ID-token validation
- `async-graphql` request context helpers
- `async-graphql` guards for auth, roles, and scopes
- WebSocket `connection_init` authentication support

## Core Types

- `AuthService<U, R>`
- `UserStore`
- `RefreshTokenStore`
- `PasswordResetTokenStore`
- `LoginChallengeStore`
- `OAuthStateStore`
- `ExternalIdentityStore`
- `OAuthTokenStore`
- `OidcProviderConfig`
- `MicrosoftEntraConfig`
- `MicrosoftEntraTenant`
- `OidcProvider`
- `OidcHttpClient`
- `ExternalUserProvisioner`
- `ClaimsMapper`
- `MicrosoftClaimsMapper`
- `AuthUser`
- `SessionContext`
- `AuthMethod`
- `MfaState`
- `MfaMethod`
- `ActiveScope`
- `AuthPayload`
- `has_scope`
- `has_any_scope`
- `has_all_scopes`
- `PasswordResetToken`
- `IssuedLoginChallenge`
- `StoredLoginChallenge`
- `TotpSecret`
- `TotpProvisioning`
- `RequireAuth`
- `RequireAnyRole`
- `RequireAllRoles`
- `RequireScope`
- `RequireAnyScope`
- `RequireAllScopes`

## Microsoft Entra ID OIDC

`agql-auth` supports Microsoft login through the OAuth2 authorization-code flow with PKCE. The crate validates the Microsoft ID token, resolves or links a local user through host-owned policy, then issues a normal local `agql-auth` session with the existing JWT access-token and rotated refresh-token behavior.

Microsoft access tokens are treated as provider tokens, not as application authorization tokens. Do not use email, UPN, display name, or `preferred_username` as an authorization identifier. For Microsoft work/school accounts, the stable external identity key is `tid + oid`; generic OIDC falls back to `iss + sub`.

Supported tenant modes:

- `MicrosoftEntraConfig::single_tenant(tenant_id, client_id, redirect_uri)`
- `MicrosoftEntraConfig::organizations(client_id, redirect_uri)`
- `MicrosoftEntraConfig::common(client_id, redirect_uri)`, with personal Microsoft accounts still rejected unless `allow_consumers` is set
- `MicrosoftEntraConfig::consumers(client_id, redirect_uri)`, only when explicitly selected

Setup outline:

1. Register an app in Microsoft Entra ID.
2. Add a web redirect URI, for example `https://app.example.com/auth/microsoft/callback`.
3. Use authorization-code flow. Do not use implicit flow.
4. Request `openid profile email`; set `request_offline_access = true` only if the host stores provider refresh tokens in encrypted storage.
5. Configure allowed tenants for multi-tenant apps.
6. Implement `OAuthStateStore` with atomic one-time consumption.
7. Implement `ExternalIdentityStore` for `(provider_name, external_subject) -> local user`.
8. Implement `ExternalUserProvisioner` and, optionally, `ClaimsMapper`.

Provider construction:

```rust
let mut entra = MicrosoftEntraConfig::single_tenant(
    "00000000-0000-0000-0000-000000000000",
    std::env::var("MICROSOFT_CLIENT_ID")?,
    "https://app.example.com/auth/microsoft/callback",
);
entra.client_secret = Some(std::env::var("MICROSOFT_CLIENT_SECRET")?);
entra.request_offline_access = false;

let provider = OidcProvider::new(
    entra.into_oidc_provider_config()?,
    std::sync::Arc::new(app_oidc_http_client),
)?;
```

The host supplies HTTP transport by implementing `OidcHttpClient`:

```rust
#[async_trait::async_trait]
impl OidcHttpClient for AppOidcHttpClient {
    async fn get_json(&self, url: &str) -> agql_auth::AuthResult<serde_json::Value> {
        // Use your HTTP client, enforce HTTPS, timeouts, and response-size limits.
        todo!()
    }

    async fn post_form_json(
        &self,
        url: &str,
        form: &[(String, String)],
    ) -> agql_auth::AuthResult<serde_json::Value> {
        // POST application/x-www-form-urlencoded and parse JSON.
        todo!()
    }
}
```

Host endpoints keep transport ownership:

```rust
async fn auth_microsoft_start(
    provider: &OidcProvider,
    state_store: &impl OAuthStateStore,
) -> agql_auth::AuthResult<String> {
    let request = provider.create_authorization_request(state_store).await?;
    Ok(request.authorization_url)
}

async fn auth_microsoft_callback<U, R, S, E, P, M>(
    auth: &AuthService<U, R>,
    provider: &OidcProvider,
    state_store: &S,
    external_identities: &E,
    provisioner: &P,
    claims_mapper: &M,
    code: String,
    state: String,
    metadata: ClientMetadata,
) -> agql_auth::AuthResult<AuthPayload>
where
    U: UserStore + 'static,
    R: RefreshTokenStore + 'static,
    S: OAuthStateStore,
    E: ExternalIdentityStore,
    P: ExternalUserProvisioner,
    M: ClaimsMapper,
{
    let login = provider
        .login_with_callback(
            auth,
            state_store,
            external_identities,
            provisioner,
            claims_mapper,
            OidcCallbackInput::code_and_state(code, state),
            metadata,
        )
        .await?;

    Ok(login.auth)
}
```

`/auth/microsoft/start` should redirect the browser to `authorization_url`. `/auth/microsoft/callback` should return or set the local `AuthPayload` tokens. Persist provider refresh tokens only if you explicitly requested `offline_access` and provide encrypted app-owned storage.

GraphQL request authentication stays the same:

```rust
let request = auth_service
    .inject_http_auth(async_graphql_request, bearer_or_cookie_token.as_deref())
    .await?;
```

## Recovery And MFA Primitives

Password reset:

- issue JWT-backed password-reset tokens
- verify token signature and expiry
- optionally enforce one-time use through `PasswordResetTokenStore`

Login challenges:

- create short-lived one-time codes for email or SMS delivery
- store only the hashed code in application storage
- verify codes with expiry, attempt, and replay protection through `LoginChallengeStore`

TOTP:

- generate new shared secrets
- build `otpauth://` provisioning URIs
- verify codes with configurable digits, period, and skew window

Roles, scopes, and structured session context:

- access tokens carry `roles`, `scopes`, and typed `ctx`
- roles remain available for coarse identity and operator meaning
- scopes are opaque strings owned by the host application
- old access tokens without `scopes` still decode with `scopes = []`
- scope helpers use exact string matching only; wildcard or prefix semantics are intentionally not built in
- access tokens carry a typed session context envelope
- typed context includes auth method, MFA satisfaction, and optional active tenant/org/catalog scope
- existing password login and refresh flows default to password auth with unsatisfied MFA and no active scope
- already-verified users can receive a full auth session through `issue_verified_user_session` or `issue_session_for_user`

Example host-app session issuance with scopes:

```rust
let payload = auth_service
    .issue_verified_user_session_with_scopes(
        user.id.clone(),
        vec!["Operator".to_string()],
        vec![
            "users.read".to_string(),
            format!("collection.{}.records.write", collection_id),
        ],
        AuthMethod::EmailCode,
        metadata,
    )
    .await?;
```

## Intended Integration

HTTP GraphQL:

- read bearer token or cookie at the transport layer
- validate with `AuthService`
- insert `AuthUser` into `async_graphql::Request`

Subscriptions:

- read `connection_init.payload`
- authenticate with `authenticate_connection_init_value`
- merge returned `async_graphql::Data` into subscription context

Application-owned storage and policy:

- implement `UserStore` and `RefreshTokenStore` using your application persistence layer
- implement `PasswordResetTokenStore` if reset tokens must be one-time use
- implement `LoginChallengeStore` to persist hashed login codes, attempt counters, and consume state
- implement `OAuthStateStore` and `ExternalIdentityStore` for OIDC login
- keep SMTP, SMS, OAuth redirects, UI flows, ORM entities, and business policy in the consuming application

## Migration Note

Consuming apps can keep existing login, refresh, logout, and GraphQL auth wiring unchanged.

To use the new recovery and challenge primitives:

- add app-owned persistence implementations for `PasswordResetTokenStore` and `LoginChallengeStore`
- call the new `AuthService` helpers from your password-reset, email-code, or SMS-code workflows
- store TOTP enrollment state in the application, not in `agql-auth`

To use OIDC login:

- add app-owned persistence implementations for `OAuthStateStore` and `ExternalIdentityStore`
- build an `OidcProvider` from `OidcProviderConfig` or `MicrosoftEntraConfig`
- issue the browser redirect with `create_authorization_request`
- complete the callback with `login_with_callback`
- use the returned local `AuthPayload` exactly like password login output

## Status

This crate is focused on reusable auth primitives and `async-graphql` integration. It does not own your application's database schema, ORM entities, transport bootstrap, email delivery, SMS delivery, or app-specific authorization policy.

## License

License not selected yet.
