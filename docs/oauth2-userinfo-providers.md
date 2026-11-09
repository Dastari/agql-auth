# OAuth 2.0 Userinfo Providers

`OAuth2Provider` signs users in with providers that implement the OAuth 2.0
authorization-code grant with PKCE but not OpenID Connect: there is no ID token
and no JWKS. GitHub is the common example. Use `OidcProvider` whenever the
provider supports OpenID Connect; a signed ID token is stronger evidence than a
userinfo response.

## What the provider does

- `create_authorization_request` stores one-time hashed state with a PKCE S256
  verifier and the hash of a random browser-binding secret in the host
  `OAuthStateStore`, and returns the authorization URL and the raw
  `browser_binding` secret. No nonce or `response_mode` is sent; the stored
  nonce is empty. The PKCE verifier is not returned.
- `handle_callback` consumes state exactly once (replayed, expired and unknown
  states are refused before any provider request), requires the browser
  binding and a matching `iss` when one is returned, exchanges the code with
  the stored verifier, and GETs the userinfo endpoint with
  `Authorization: Bearer <access token>`.
- The outcome holds the consumed state, an `OAuth2TokenResponse` (in memory
  only, `Debug`-redacted, overwritten on drop) and an `OAuth2UserProfile`:
  subject, email, `email_verified`, name, picture and the raw JSON object.
- `login_with_callback` runs `handle_callback`, looks up the identity linked to
  `(provider_name, subject)`, asks the host's `OAuth2UserProvisioner` for the
  local user, re-reads that user from the `AuthService` user store, links or
  updates the identity and issues a local session with `AuthMethod::OAuth2`.
  A disabled user fails with `UserDisabled` and a missing user with
  `ExternalLoginRejected`, before any identity is linked and before a session
  is issued.

`agql-auth` stores no provider token and creates no user. Sign-up and
email-trust policy stay with the host, in the provisioner. Identities are keyed
by `(provider_name, subject)`.

The token exchange and the userinfo request are not public API. A userinfo
response proves only that a token is valid, not which client it was issued to,
so a token supplied by a client would sign in whoever it belongs to. Sign users
in only through the callback.

`provider_name` must be unique across every `OAuth2Provider` and
`OidcProvider` the host runs. Never give an OIDC provider and an OAuth 2.0
provider the same name. They share the state-store and identity namespace,
and the empty-nonce cross-check only refuses mistakes; it does not make a
shared name safe.

`client_secret` is deserialized but never serialized, so a serialized
configuration does not carry the secret. Supply it again from secret storage.

## Configuration

Endpoints are explicit (no discovery). They must be `https://` URLs; `http://`
is accepted only for `localhost`, `127.0.0.1` and `[::1]`. The authorization
endpoint must not already contain protocol parameters such as `state`.
`redirect_uri` follows the same rule and must not contain a fragment. Give each
provider its own redirect URI and route. `state_ttl` is at most one hour
(`MAX_OAUTH_STATE_TTL_SECONDS`).

`issuer` (optional) is the authorization server's issuer identifier. A callback
`iss` parameter (RFC 9207) must equal it, and a callback carrying `iss` is
refused when no `issuer` is configured. Set
`require_authorization_response_iss` when the provider always returns `iss`.
`issuer` is also the default `private_key_jwt` audience.

`OAuth2ProfileMapping` locates profile values with JSON pointers:

- `subject_pointer` (required): a non-empty string or an integer, normalized to
  its decimal string. Missing, empty, non-scalar, fractional, control-character
  or over-255-byte values return `AuthError::OAuthMissingSubject`.
- `email_pointer`, `name_pointer`, `picture_pointer`: optional strings. Values
  longer than `MAX_OAUTH2_EMAIL_LENGTH` (320), `MAX_OAUTH2_NAME_LENGTH` (512)
  and `MAX_OAUTH2_PICTURE_LENGTH` (2,048) bytes are treated as absent.
- `email_verification`: `Unknown` (no statement), `Pointer(..)` (a JSON boolean
  or the exact strings `"true"`/`"false"`; anything else is `None`), or
  `ProviderVerifiesAll` for providers that document that every profile email
  is verified.

Only `email_verified == Some(true)` asserts a verified address. Treat `None`
and `Some(false)` as unverified.

### Verified-email list

Some providers return no verified email in the profile. `OAuth2VerifiedEmailList`
adds a second bearer GET whose response is an array of entries (or an array at
`entries_pointer`). The first entry that is verified, and primary for
`PrimaryVerified`, replaces the profile email with `email_verified =
Some(true)`. It is consulted only when the profile did not already yield
`Some(true)`. When nothing qualifies the profile email is kept unchanged. A
failed request, a non-array response, or more than 100 entries fails the
callback with `OAuthUserInfo`.

### Client authentication

`token_endpoint_auth_method` selects `client_secret_post` (default),
`client_secret_basic` or `private_key_jwt`. See
[OIDC form_post and signed client credentials](oidc-form-post-and-client-credentials.md).
Token requests always send `Accept: application/json`; GitHub returns form
encoding otherwise.

## HTTP client contract

`OAuth2Provider::new` requires `OidcHttpClient::supports_request_headers()` to
return `true`, and the client must implement `get_json_with_headers` and
`post_form_json_with_headers` sending every supplied header. Return `Err` for
non-success statuses (for example a userinfo 401) and for non-JSON bodies.
Bound response sizes and timeouts, and never log headers, form values or
bodies. Do not follow redirects: return `Err` for every 3xx response, since a
followed `307`/`308` re-sends the secret, code, verifier or bearer token to the
redirect target. GitHub's API also requires a `User-Agent` header. A negative
`expires_in` fails the exchange.

## Browser binding

`OAuth2ProviderConfig::browser_binding` defaults to
`OAuthBrowserBinding::Required`. Store `request.browser_binding` in a cookie on
the browser that starts the flow, and pass it back as
`OidcCallbackInput::browser_binding`:

- `HttpOnly`, `Secure`, `Path=/`, ideally with the `__Host-` prefix;
- `SameSite=Lax`: the provider's query redirect is a top-level `GET`;
- `Max-Age` at most `state_ttl`; clear it after the callback.

A callback without the cookie value, or with another value, fails with
`InvalidOAuthState` after its state is consumed, so an attacker cannot make a
victim's browser complete a flow the attacker started (login CSRF). Hosts that
already tie `state` to the browser in their own server-side session may set
`OAuthBrowserBinding::NotRequiredHostBindsState`.

## GitHub example

```rust,ignore
use std::sync::Arc;
use agql_auth::{
    AuthResult, ExternalIdentity, OAuth2Provider, OAuth2ProviderConfig,
    OAuth2UserProfile, OAuth2UserProvisioner, OidcCallbackInput,
    ProvisionedExternalUser,
};

let github = OAuth2Provider::new(
    OAuth2ProviderConfig::github(
        std::env::var("GITHUB_CLIENT_ID")?,
        std::env::var("GITHUB_CLIENT_SECRET")?,
        "https://app.example.com/auth/github/callback",
    ),
    Arc::new(app_http_client),
)?;

// Start route.
let request = github.create_authorization_request(&state_store).await?;
set_cookie(
    "__Host-github_binding",
    request.browser_binding.as_deref().expect("required by default"),
    "Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600",
);
// Redirect the browser to request.authorization_url.

// Callback route.
struct Provisioner;

#[async_trait::async_trait]
impl OAuth2UserProvisioner for Provisioner {
    async fn resolve_oauth2_user(
        &self,
        profile: &OAuth2UserProfile, // subject is GitHub's numeric user id
        existing: Option<&ExternalIdentity>,
    ) -> AuthResult<ProvisionedExternalUser> {
        // Find or create the local user; apply sign-up and email-trust policy.
        let user_id = match existing {
            Some(identity) => identity.user_id.clone(),
            None => create_or_link_user(profile).await?,
        };
        Ok(ProvisionedExternalUser::new(user_id, roles, scopes))
    }
}

let result = github
    .login_with_callback(
        &auth_service,
        &state_store,
        &external_identity_store,
        &Provisioner,
        OidcCallbackInput {
            code: query.code,
            state: query.state,
            iss: query.iss,
            browser_binding: cookie("__Host-github_binding"),
            error: query.error,
            error_description: None,
        },
        client_metadata,
    )
    .await?; // UserDisabled / ExternalLoginRejected for disabled or missing users
let session = result.auth; // local access and refresh tokens
```

`handle_callback` remains available when the host only needs the profile, but
it issues no session and does not check the local account. A host that issues
its own session after it must load the user and refuse a disabled account
itself: `issue_verified_user_session*` does not.

`OAuth2ProviderConfig::github` is equivalent to:

| Setting | Value |
|---------|-------|
| `authorization_endpoint` | `https://github.com/login/oauth/authorize` |
| `token_endpoint` | `https://github.com/login/oauth/access_token` |
| `userinfo_endpoint` | `https://api.github.com/user` |
| `scopes` | `read:user`, `user:email` |
| `subject_pointer` | `/id` |
| `email_verification` | `Unknown` |
| `name_pointer` / `picture_pointer` | `/name` / `/avatar_url` |
| `verified_email_list` | `https://api.github.com/user/emails`, primary and verified |

## Errors

| Condition | Variant |
|-----------|---------|
| Unknown, consumed, or missing state; state from an OIDC or `form_post` flow; missing or wrong browser binding | `InvalidOAuthState` |
| Expired state | `OAuthStateExpired` |
| Provider error callback (state not consumed) | `OAuthProviderError` |
| Missing code (state not consumed) | `OAuthCallback` |
| `iss` returned without a configured `issuer`, a different `iss`, or a required `iss` missing | `OAuthCallback` |
| Token request failure, `error` response, non-object body, missing `access_token`, non-bearer `token_type`, invalid or negative `expires_in` | `OAuthTokenExchange` |
| Userinfo or verified-email list failure or invalid body | `OAuthUserInfo` |
| No usable subject | `OAuthMissingSubject` |
| `login_with_callback`: provisioned user missing, or a different user for a linked identity | `ExternalLoginRejected` |
| `login_with_callback`: provisioned user disabled | `UserDisabled` |

See [public error codes](public-error-codes.md) for their stable codes.
