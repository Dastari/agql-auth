# Authorization, Scopes, And Guards

`agql-auth` issues local access tokens containing local authorization data. OIDC
or Microsoft claims may influence roles and scopes during provisioning, but
GraphQL authorization should use the local `AuthUser` attached to the request.

## Access-Token Claims

Local access tokens preserve this claim shape:

- `sub`: local user ID
- `sid`: local session ID
- `roles`: local roles
- `scopes`: local scopes
- `ctx`: typed `SessionContext`
- `iss`: configured issuer
- `aud`: configured audience
- `exp`: expiry timestamp
- `iat`: issued-at timestamp

The `ctx` claim contains the local authentication method, MFA state, and
optional active scope.

## Auth Methods

`SessionContext.auth_method` records how the local session was issued:

- `Password`
- `EmailCode`
- `SmsCode`
- `TotpStepUp`
- `ServiceToken`
- `Oidc`
- `MicrosoftOidc`

For external login, Microsoft or OIDC tokens are used only to verify the login
event. The resulting GraphQL request is authorized with local roles, scopes, and
session context.

## Generic Principals

`AuthUser` remains the user-session type. For code that can accept either user
sessions or API/service tokens, use `AuthPrincipal`:

- `AuthPrincipal::User(AuthUser)`
- `AuthPrincipal::ApiToken(ApiTokenPrincipal)`

`AuthPrincipal` exposes `subject()`, `roles()`, `scopes()`, scope helper
methods, and API-token accessors for audience, resource binding, token ID, and
expiry. API-token principals return an empty role list unless the host models
roles separately.

## Scope Matching

Scope matching is exact string matching. The crate does not interpret wildcard
or hierarchical scopes.

```rust
use agql_auth::{has_all_scopes, has_any_scope, has_scope};

assert!(has_scope(&user.scopes, "orders.read"));
assert!(has_any_scope(&user.scopes, &["orders.read", "orders.write"]));
assert!(has_all_scopes(&user.scopes, &["orders.read", "profile.read"]));
```

`AuthUser` exposes the same checks:

```rust
if user.has_scope("orders.read") {
    // ...
}
```

## GraphQL Guards

Use guards when a resolver has a fixed authorization requirement:

```rust
use agql_auth::{
    RequireAllRoles, RequireAllScopes, RequireAnyRole, RequireAnyScope, RequireAuth, RequireScope,
};

#[Object]
impl Query {
    #[graphql(guard = "RequireAuth::new()")]
    async fn viewer(&self) -> Viewer {
        // ...
    }

    #[graphql(guard = "RequireAnyRole::new([\"Admin\", \"Operator\"])")]
    async fn admin_view(&self) -> AdminView {
        // ...
    }

    #[graphql(guard = "RequireScope::new(\"orders.read\")")]
    async fn orders(&self) -> Vec<Order> {
        // ...
    }

    #[graphql(guard = "RequireAllScopes::new([\"orders.read\", \"profile.read\"])")]
    async fn account_orders(&self) -> Vec<Order> {
        // ...
    }
}
```

Use resolver code when authorization depends on object ownership, tenant
membership, or other dynamic data.

For resolvers that accept either a user session or an API token, use the generic
principal guards:

```rust
use agql_auth::{
    RequireAllPrincipalScopes, RequireAnyPrincipalScope, RequirePrincipal,
    RequirePrincipalScope,
};

#[Object]
impl Query {
    #[graphql(guard = "RequirePrincipal::new()")]
    async fn viewer(&self) -> Viewer {
        // ...
    }

    #[graphql(guard = "RequirePrincipalScope::new(\"inventory.read\")")]
    async fn inventory(&self) -> Vec<Item> {
        // ...
    }
}
```

## Reading The Authenticated User

`inject_http_auth` and `authenticate_connection_init_value` attach `AuthUser` to
the `async-graphql` request data. Resolvers can read it with:

```rust
use agql_auth::{auth_user_from_ctx, auth_user_from_ctx_opt};

let required_user = auth_user_from_ctx(ctx)?;
let optional_user = auth_user_from_ctx_opt(ctx);
```

`auth_user_from_ctx` returns an authentication error when no user is present.

For generic user-or-token access, use:

```rust
use agql_auth::{principal_from_ctx, principal_from_ctx_opt};

let principal = principal_from_ctx(ctx)?;
let optional_principal = principal_from_ctx_opt(ctx);
```
