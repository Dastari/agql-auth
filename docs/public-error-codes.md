# Public Error Code Contract

`AuthError` separates three layers:

| Layer | API | Audience |
|-------|-----|----------|
| Stable public code | `AuthError::public_code()` | Clients, GraphQL extensions |
| Safe public message | `AuthError::public_message()` / `Display` | Clients |
| Internal detail | `AuthError::diagnostic()` / `internal_detail()` / `Debug` | Server logs and tracing |

`Display` (`to_string()`) is the safe public message. A resolver that returns
an `AuthError` through a plain `?` therefore sends only that message; it carries
no `extensions.code`, so prefer `.extend()` (`ErrorExtensions`) or
`map_err(|err| err.extend())` to attach the stable code. GraphQL
`ErrorExtensions` exposes only the safe public message and code (plus
`retryAfterSeconds` for rate-limit errors). OIDC discovery strings, store
messages, hashing errors, HTTP bodies, configuration text and stack traces are
never sent to clients.

Log the detail explicitly:

```rust
match auth.login(principal, password, metadata).await {
    Ok(payload) => Ok(payload),
    Err(err) => {
        tracing::warn!(error = %err.diagnostic(), code = err.public_code(), "login failed");
        Err(err.extend())
    }
}
```

## Stable Public Codes

| Code | Typical causes |
|------|----------------|
| `UNAUTHENTICATED` | Missing principal, missing connection-init auth, failed OIDC identity |
| `FORBIDDEN` | Role/scope/channel guard failure, rejected external login |
| `INVALID_ACCESS_TOKEN` | Bad signature, wrong audience/issuer/alg/purpose/claims |
| `ACCESS_TOKEN_EXPIRED` | Expired access JWT |
| `TOKEN_REVOKED` | Revoked session/token via status checker |
| `INVALID_API_TOKEN` | Invalid, expired-as-invalid, or revoked opaque API token |
| `RATE_LIMITED` | Throttled or locked credential/request flows |
| `AUTH_SERVICE_UNAVAILABLE` | Store failures, OIDC transport failures, token creation failures |
| `INVALID_CONFIGURATION` | Host misconfiguration (usually fail-fast at startup) |

OAuth 2.0 (`OAuth2Provider`) failures are distinct variants that map onto the
stable codes above, so hosts branch on the variant and clients see no provider
detail:

| Variant | Code |
|---------|------|
| `InvalidOAuthState` / `OAuthStateExpired` / `OAuthStateReplayed` | `INVALID_OAUTH_STATE` / `OAUTH_STATE_EXPIRED` / `OAUTH_STATE_REPLAYED` |
| `OAuthProviderError` (error callback, e.g. cancelled) | `UNAUTHENTICATED` |
| `OAuthCallback` (malformed callback, missing code) | `UNAUTHENTICATED` |
| `OAuthTokenExchange` | `AUTH_SERVICE_UNAVAILABLE` |
| `OAuthUserInfo` (userinfo or verified-email list) | `AUTH_SERVICE_UNAVAILABLE` |
| `OAuthMissingSubject` | `UNAUTHENTICATED` |

Their internal detail is a fixed diagnostic string; provider response bodies,
`error_description` text and tokens are never copied into an `AuthError`.

Additional codes remain available for specific flows (refresh, password reset,
login challenges, TOTP). Prefer the table above for cross-service contracts.

## Assurance Decisions

`AssuranceEvaluationState::graphql_extension_code()` is the stable mapping for
operation assurance:

| Evaluation state | `extensions.code` |
|------------------|-------------------|
| `Unauthenticated` | `UNAUTHENTICATED` |
| `StepUpRequired { .. }` | `STEP_UP_REQUIRED` |
| `Forbidden { .. }` | `FORBIDDEN` |

`AssuranceDenialCode` preserves the detailed policy reason and its own stable
wire string. Do not parse `AssuranceDenial::public_message()` or internal
diagnostics to choose a GraphQL code.

## Before / After

Before (unsafe for clients):

```text
message: "oidc discovery failed: http 500 from https://login.example/..."
extensions.code: OIDC_DISCOVERY_FAILED
```

After:

```text
message: "authentication service unavailable"
extensions.code: AUTH_SERVICE_UNAVAILABLE
```

Server diagnostics use `err.diagnostic()` or `internal_detail()` in logs.

## Migration

This is a deliberate hardening change in `0.7`. Callers that asserted on full
`Display` strings inside GraphQL responses must switch to `extensions.code` or
`public_code()`.

Since `0.27`, `Display` itself is the safe public message. Logging that used
`err.to_string()` or `{err}` to capture internal detail must switch to
`err.diagnostic()` (or `{err:?}`); the old diagnostic text is unchanged there.
