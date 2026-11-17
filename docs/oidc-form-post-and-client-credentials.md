# OIDC form_post and Signed Client Credentials

This guide covers three opt-in `OidcProvider` options and the client
authentication shared with `OAuth2Provider`. Defaults are unchanged:
`response_mode=query` and `client_secret_post`.

## Response mode

`OidcProviderConfig::response_mode` is `OAuthResponseMode::Query` (default) or
`OAuthResponseMode::FormPost`. The value is sent as `response_mode` and stored
in `OAuthLoginState::response_mode`.

For `form_post` the provider delivers `code`, `state`, `iss` (RFC 9207, when
supported), `error` and `error_description` as an
`application/x-www-form-urlencoded` POST body. The
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
  rely on such a cookie to find the flow.

### Browser binding for form_post

Browser binding is required by default (`OAuthBrowserBinding::Required`):
`create_authorization_request` returns `request.browser_binding`, a random
secret whose SHA-256 hash is stored in the state, and the callback must pass the
raw value as `OidcCallbackInput::browser_binding`. Without it a victim's browser
could be made to finish a flow an attacker started (login CSRF). A missing or
wrong value fails with `InvalidOAuthState` after the state is consumed.

Because the `form_post` callback is a cross-site POST, the cookie carrying the
value must be `SameSite=None; Secure; HttpOnly` (with the `__Host-` prefix,
`Path=/`, and `Max-Age` at most `state_ttl`), or the host must bind the flow
another way. One alternative: have the POST route store the parsed form under a
fresh one-time handoff ID, `303`-redirect to a same-site `GET` route, and call
`handle_callback_in_mode` there, where a `SameSite=Lax` binding cookie is sent.
A host that ties `state` to the browser through its own server-side session
may set `browser_binding = OAuthBrowserBinding::NotRequiredHostBindsState`.

- Answer with `303 See Other` and `Cache-Control: no-store` so a refresh does
  not resubmit the code.
- Give each provider its own redirect URI and route; a response must reach
  only the provider that started it.
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

The HTTP client must not follow redirects: a client that follows a `307` or
`308` re-posts the client secret or assertion, the code and the PKCE verifier to
the redirect target. Return `Err` for every 3xx response.

The token exchange and the userinfo request are internal to the callback; there
is no public API that turns an arbitrary access token into an identity.

### ClientJwtSigner

`ClientJwtSigner::from_pem(algorithm, pem, ClientJwtClaims)` parses an
in-memory PEM private key (ES256, ES384, RS256 or PS256) and proves it with a
probe signature, so a mismatched key fails at startup. The key is never
serialized (`client_jwt` is `#[serde(skip)]`), never logged and redacted from
`Debug`. The PEM bytes are not retained. Key storage is the host's concern.

A fresh JWT is minted for every token request:

- header: `alg`, `typ: JWT`, optional `kid`, and optional `x5t#S256`
  (`with_x509_sha256_thumbprint`, the unpadded base64url SHA-256 of the DER
  certificate, as Microsoft Entra certificate credentials use);
- claims: `iss`, `sub`, `aud`, `iat`, `exp = iat + lifetime`, and optional
  `nbf = iat` (`with_not_before`);
- `aud` is the configured audience, else for `PrivateKeyJwt` the authorization
  server's issuer identifier (the validated discovery `issuer` of a generic
  `OidcProvider`, or `OAuth2ProviderConfig::issuer`). Microsoft Entra
  providers use the token endpoint, which Microsoft documents; an
  `OAuth2Provider` without `issuer` uses its configured token endpoint. A
  signed `client_secret` defaults to the token endpoint;
- `iat` is the provider clock minus `issued_at_skew` (default 30 s, at most
  300 s), so identity providers whose clock runs behind do not reject a
  future `iat`. The total lifetime `exp - iat` stays `lifetime`, and the JWT
  is valid for `lifetime - issued_at_skew` after minting;
- `jti` (256 random bits) only for `PrivateKeyJwt`.

With `PrivateKeyJwt` the JWT is the `client_assertion`. With
`ClientSecretPost`/`ClientSecretBasic` it is the `client_secret` value, a
signed client secret. Lifetimes are whole seconds, at least one second longer
than `issued_at_skew` and at most `MAX_CLIENT_JWT_LIFETIME_SECONDS`
(15,777,000 s, Apple's maximum). The default is five minutes. `client_secret` and `client_jwt` are mutually exclusive.

`PrivateKeyJwt` is stricter: `iss` and `sub` must both equal the client ID and
the lifetime is at most `MAX_PRIVATE_KEY_JWT_LIFETIME_SECONDS` (600 s).
Configuration fails otherwise.

Static client secrets in provider configurations, transient copies in token
requests, and provider tokens in `OidcTokenResponse` / `OAuth2TokenResponse`
are overwritten when dropped (best effort: copies the host makes, and earlier
reallocations, are not covered).

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
            iss: form.iss,
            // From the SameSite=None binding cookie set at the start route.
            browser_binding: binding_cookie,
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
