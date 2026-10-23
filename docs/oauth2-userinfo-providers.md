# OAuth 2.0 Userinfo Providers

`OAuth2Provider` signs users in with providers that implement the OAuth 2.0
authorization-code grant with PKCE but not OpenID Connect: there is no ID token
and no JWKS. GitHub is the common example. Use `OidcProvider` whenever the
provider supports OpenID Connect; a signed ID token is stronger evidence than a
userinfo response.

## What the provider does

- `create_authorization_request` stores one-time hashed state with a PKCE S256
  verifier in the host `OAuthStateStore` and returns the authorization URL. No
  nonce or `response_mode` is sent; the stored nonce is empty.
- `handle_callback` consumes state exactly once (replayed, expired and unknown
  states are refused before any provider request), exchanges the code with the
  stored verifier, and GETs the userinfo endpoint with
  `Authorization: Bearer <access token>`.
- The outcome holds the consumed state, an `OAuth2TokenResponse` (in memory
  only, `Debug`-redacted) and an `OAuth2UserProfile`: subject, email,
  `email_verified`, name, picture and the raw JSON object.

`agql-auth` stores no provider token and creates no user. Account linking,
sign-up and email-trust policy stay with the host. Key identities by
`(provider_name, subject)`.

## Configuration

Endpoints are explicit (no discovery). They must be `https://` URLs; `http://`
is accepted only for `localhost`, `127.0.0.1` and `[::1]`. The authorization
endpoint must not already contain protocol parameters such as `state`.

`OAuth2ProfileMapping` locates profile values with JSON pointers:

- `subject_pointer` (required): a non-empty string or an integer, normalized to
  its decimal string. Missing, empty, non-scalar, fractional, control-character
  or over-255-byte values return `AuthError::OAuthMissingSubject`.
- `email_pointer`, `name_pointer`, `picture_pointer`: optional strings.
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
Bound response sizes and timeouts, disable redirects, and never log headers,
form values or bodies. GitHub's API also requires a `User-Agent` header.

## GitHub example

```rust,ignore
use std::sync::Arc;
use agql_auth::{OAuth2Provider, OAuth2ProviderConfig, OidcCallbackInput};

let github = OAuth2Provider::new(
    OAuth2ProviderConfig::github(
        std::env::var("GITHUB_CLIENT_ID")?,
        std::env::var("GITHUB_CLIENT_SECRET")?,
        "https://app.example.com/auth/github/callback",
    ),
    Arc::new(app_http_client),
)?;

let request = github.create_authorization_request(&state_store).await?;
// Redirect the browser to request.authorization_url.

let outcome = github
    .handle_callback(
        &state_store,
        OidcCallbackInput {
            code: query.code,
            state: query.state,
            error: query.error,
            error_description: None,
        },
    )
    .await?;
let profile = outcome.profile; // subject is GitHub's numeric user id
```

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
| Unknown, consumed, or missing state; state from an OIDC or `form_post` flow | `InvalidOAuthState` |
| Expired state | `OAuthStateExpired` |
| Provider error callback (state not consumed) | `OAuthProviderError` |
| Missing code (state not consumed) | `OAuthCallback` |
| Token request failure, `error` response, non-object body, missing `access_token`, non-bearer `token_type` | `OAuthTokenExchange` |
| Userinfo or verified-email list failure or invalid body | `OAuthUserInfo` |
| No usable subject | `OAuthMissingSubject` |

See [public error codes](public-error-codes.md) for their stable codes.
