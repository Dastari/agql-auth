# Authorization, Scopes, And Guards

`agql-auth` issues local access tokens containing local authorization data. OIDC
or Microsoft claims may influence roles and scopes during provisioning, but
GraphQL authorization should use the local `AuthUser` attached to the request.

## Access-Token Claims

Local access tokens preserve this claim shape:

- `sub`: local user ID
- `sid`: local session ID
- `roles`: local roles
- `scope`: local scopes as one space-delimited OAuth string
- `ctx`: typed `SessionContext`
- `iss`: configured issuer
- `aud`: configured audience
- `exp`: expiry timestamp
- `iat`: issued-at timestamp

The `ctx` claim contains the local authentication method, MFA state, and
optional active scope.

After validation, `scope` is normalized into the public
`AuthUser::scopes: Vec<String>`. This in-process representation and all guard
APIs are unchanged. During a bounded migration, validators can also read the
pre-0.14 `scopes` array; see
[Access-token scope claims](access-token-scope-claims.md).

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

Direct scope helpers remain exact string matching. This preserves existing
runtime behavior:

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

For wildcard or hierarchical scopes, configure a `ScopeMatch` implementation
and inject it through `AuthRuntime`. Guards read the runtime matcher and fall
back to exact matching when no runtime is present:

```rust
use std::sync::Arc;
use agql_auth::{AuthRuntime, HierarchicalScopeMatch};

let request = request.data(AuthRuntime::new(Arc::new(
    HierarchicalScopeMatch::with_defaults(),
)));
```

`AuthService`, `AccessTokenValidator`, and `CombinedAuth` inject
`AuthRuntime` after successful authentication. See
[Scope matching](scope-matching.md) for the normative algorithm and golden
vectors.

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
principal guards. `CombinedAuth` can inject either credential type into one
`AuthPrincipal`:

```rust
use agql_auth::{
    CombinedAuth, RequireAllPrincipalScopes, RequireAnyPrincipalScope,
    RequirePrincipal, RequirePrincipalScope,
};

let request = CombinedAuth::new(&access_token_validator, &api_token_service)
    .inject_http_auth(request, authorization_header, metadata)
    .await?;

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

## Channel Identity

Hosts that verify a channel outside this crate can inject `ChannelIdentity`.
The crate does not parse certificates or verify channel credentials.

```rust
use agql_auth::{ChannelIdentity, RequireChannelScheme};

let request = request.data(
    ChannelIdentity::new("mtls", "device-1").with_claim("fingerprint", "sha256:..."),
);

#[Object]
impl Mutation {
    #[graphql(guard = "RequireChannelScheme::new(\"mtls\")")]
    async fn device_action(&self) -> bool {
        true
    }
}
```
