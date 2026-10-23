# Public Error Code Contract

`AuthError` separates three layers:

| Layer | API | Audience |
|-------|-----|----------|
| Stable public code | `AuthError::public_code()` | Clients, GraphQL extensions |
| Safe public message | `AuthError::public_message()` | Clients |
| Internal detail | `AuthError::internal_detail()` / `Display` | Server logs and tracing |

GraphQL `ErrorExtensions` exposes only the safe public message and code (plus
`retryAfterSeconds` for rate-limit errors). OIDC discovery strings, store
messages, HTTP bodies, configuration dumps, and stack traces are never sent to
clients by default.

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

Server diagnostics still use `err.to_string()` / `internal_detail()` in logs.

## Migration

This is a deliberate hardening change in `0.7`. Callers that asserted on full
`Display` strings inside GraphQL responses must switch to `extensions.code` or
`public_code()`.
