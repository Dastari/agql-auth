# WebSocket Reauthorization

Long-lived GraphQL subscriptions and device channels need more than
connection-init authentication. `agql-auth` provides generic hooks; hosts own
transport and storage.

## Connection Init

```rust
let user = validator.authenticate_connection_init_value(
    &payload,
    &["authorization", "Authorization"],
)?;
```

Missing auth returns `MissingConnectionInitAuth` (public code
`UNAUTHENTICATED`). Invalid tokens fail closed and never become anonymous.

## Status Checker

```rust
use agql_auth::{TokenStatus, TokenStatusChecker, TokenStatusRequest};

#[async_trait::async_trait]
impl TokenStatusChecker for MyRevocationStore {
    async fn check(&self, request: TokenStatusRequest<'_>) -> agql_auth::AuthResult<TokenStatus> {
        // Look up jti / session_id / principal against your revocation store.
        Ok(TokenStatus::Active)
    }
}
```

Use `ReauthorizationPolicy` to derive the next check deadline from token expiry:

```rust
use agql_auth::{AccessTokenMetadata, ReauthorizationPolicy};

let policy = ReauthorizationPolicy::default(); // fail-closed
let deadline = policy.next_deadline(now, &user.token_claims, connection_started_at);
```

## Failure Modes

| Mode | Behavior |
|------|----------|
| `FailClosed` (default) | Checker errors become auth failures |
| `FailOpen` | Checker errors are treated as active (explicit opt-in) |

Security-sensitive defaults fail closed.

## Recommended Host Loop

1. Authenticate `connection_init`.
2. Store principal, `jti`, session id, and next deadline.
3. On each high-risk operation or when `now >= deadline`, call the status checker.
4. On `Revoked` / `Expired`, close the socket with a safe public error.
5. Never log raw tokens from the connection payload.
