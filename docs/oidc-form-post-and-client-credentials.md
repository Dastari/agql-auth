# OIDC form_post and Signed Client Credentials

This guide covers three opt-in `OidcProvider` options and the client
authentication shared with `OAuth2Provider`. Defaults are unchanged:
`response_mode=query` and `client_secret_post`.

## Response mode

`OidcProviderConfig::response_mode` is `OAuthResponseMode::Query` (default) or
`OAuthResponseMode::FormPost`. The value is sent as `response_mode` and stored
in `OAuthLoginState::response_mode`.

For `form_post` the provider delivers `code`, `state`, `error` and
`error_description` as an `application/x-www-form-urlencoded` POST body. The
host parses that body into the transport-neutral `OidcCallbackInput` and calls
`handle_callback_in_mode(store, input, OAuthResponseMode::FormPost)` (or
`login_with_callback_in_mode`). The existing `handle_callback` and
`login_with_callback` mean query delivery.

- A delivery mode other than the configured mode is refused before the state is
  consumed, so a forged GET cannot burn a `form_post` state.
- A consumed state bound to another mode is refused, which also covers a
  provider reconfigured between start and callback.
- Stores must persist `response_mode`. A `form_post` state reloaded without it
  reads as `query` and its callback is refused.

### Cross-site POST, CSRF and SameSite

A `form_post` callback is a cross-site top-level POST from the provider:

- Exempt the callback route from same-site CSRF-token checks. The one-time
  hashed state is the request's anti-forgery token: unknown, replayed and
  expired states are refused.
- Browsers do not send `SameSite=Lax` or `Strict` cookies on that POST. Do not
  rely on such a cookie to find the flow; `agql-auth` needs only `state`.
- The server-side state does not identify the browser that started the flow. To
  prevent login CSRF, bind completion to the initiating browser: use a
  `SameSite=None; Secure; HttpOnly` cookie set at start, or redirect to a
  handoff that the initiating client redeems with a secret it holds.
- Answer with `303 See Other` and `Cache-Control: no-store` so a refresh does
  not resubmit the code.
- Fields outside `OidcCallbackInput`, such as Apple's first-login `user` JSON,
  are unsigned. Treat them only as display hints.

## Token-endpoint client authentication

`token_endpoint_auth_method` (`TokenEndpointAuthMethod`) applies to both
`OidcProviderConfig` and `OAuth2ProviderConfig`:

| Method | Request |
|--------|---------|
| `ClientSecretPost` (default) | `client_id` and the optional secret in the form body |
| `ClientSecretBasic` | `Authorization: Basic` with form-urlencoded `client_id:secret`, no credentials in the body |
| `PrivateKeyJwt` | `client_id`, `client_assertion_type` (`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`) and a fresh `client_assertion` |

`ClientSecretBasic` needs an HTTP client whose `supports_request_headers()` is
`true`. Construction fails otherwise rather than dropping the header.
`ClientSecretPost` and `PrivateKeyJwt` keep using `post_form_json`.

### ClientJwtSigner

`ClientJwtSigner::from_pem(algorithm, pem, ClientJwtClaims)` parses an
in-memory PEM private key (ES256, ES384, RS256 or PS256) and proves it with a
probe signature, so a mismatched key fails at startup. The key is never
serialized (`client_jwt` is `#[serde(skip)]`), never logged and redacted from
`Debug`. The PEM bytes are not retained. Key storage is the host's concern.

A fresh JWT is minted for every token request:

- header: `alg`, `typ: JWT`, optional `kid`;
- claims: `iss`, `sub`, `aud` (the configured audience, or the token endpoint
  URL), `iat` (provider clock) and `exp = iat + lifetime`;
- `jti` (256 random bits) only for `PrivateKeyJwt`.

With `PrivateKeyJwt` the JWT is the `client_assertion`. With
`ClientSecretPost`/`ClientSecretBasic` it is the `client_secret` value, a
signed client secret. Lifetimes must be positive and at most
`MAX_CLIENT_JWT_LIFETIME_SECONDS` (15,777,000 s, Apple's maximum); the default
is five minutes. `client_secret` and `client_jwt` are mutually exclusive.

## `email_verified`

`ValidatedOidcClaims::email_verified` is `Some(bool)` for a JSON boolean or the
exact strings `"true"`/`"false"`. Any other value is `None`. Only `Some(true)`
asserts a verified address; whether to trust it is host policy.

## Sign in with Apple example

```rust,ignore
use std::sync::Arc;
use agql_auth::{
    ClientJwtAlgorithm, ClientJwtClaims, ClientJwtSigner, OAuthResponseMode,
    OidcCallbackInput, OidcProvider, OidcProviderConfig,
};

let services_id = "com.example.web";
let mut config = OidcProviderConfig::new(
    "apple",
    "https://appleid.apple.com/.well-known/openid-configuration",
    services_id,
    "https://app.example.com/auth/apple/callback",
);
config.requested_scopes = vec!["openid".into(), "name".into(), "email".into()];
config.response_mode = OAuthResponseMode::FormPost; // required with name/email
config.client_jwt = Some(ClientJwtSigner::from_pem(
    ClientJwtAlgorithm::ES256,
    apple_p8_key_bytes, // decrypted in memory from host secret storage
    ClientJwtClaims::new(apple_team_id, services_id)
        .with_key_id(apple_key_id)
        .with_audience("https://appleid.apple.com"),
)?);
let apple = OidcProvider::new(config, Arc::new(app_http_client))?;

// POST callback route: parse the form body.
let outcome = apple
    .handle_callback_in_mode(
        &state_store,
        OidcCallbackInput {
            code: form.code,
            state: form.state,
            error: form.error,
            error_description: None,
        },
        OAuthResponseMode::FormPost,
    )
    .await?;
let verified = outcome.claims.email_verified == Some(true);
```

Apple's issuer `https://appleid.apple.com`, RS256 ID tokens, nonce, audience
and expiry checks are the standard `OidcProvider` validation.
