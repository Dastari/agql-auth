use agql_auth::{
    AuthUser, GraphqlRefreshCookieConfig, GraphqlRefreshCookieDirective, GraphqlTopLevelField,
    RequireScope, auth_user_from_ctx, graphql_refresh_cookie_directive,
};
use async_graphql::{
    Context, EmptyMutation, EmptySubscription, Object, Request, Response, Schema, Value,
};
use serde_json::json;

struct Query;

#[Object]
impl Query {
    #[graphql(guard = "RequireScope::new(\"records.read\")")]
    async fn subject(&self, ctx: &Context<'_>) -> async_graphql::Result<String> {
        Ok(auth_user_from_ctx(ctx)?.user_id.clone())
    }
}

#[tokio::test]
async fn real_auth_guard_context_and_public_errors() {
    let schema = Schema::build(Query, EmptyMutation, EmptySubscription).finish();
    let denied = schema.execute("{ subject }").await;
    assert_eq!(denied.errors.len(), 1);
    assert_eq!(
        denied.errors[0].extensions.as_ref().unwrap().get("code"),
        Some(&Value::from("UNAUTHENTICATED"))
    );

    // Use public serialization to construct the domain UUID/time-bearing context
    // without requiring async-graphql's optional uuid/time scalar features.
    let mut user: AuthUser = serde_json::from_value(json!({
        "user_id": "fixture-user",
        "session_id": "00000000-0000-0000-0000-000000000001",
        "roles": [],
        "scopes": ["records.read"]
    }))
    .unwrap();
    let allowed = schema
        .execute(Request::new("{ subject }").data(user.clone()))
        .await;
    assert!(allowed.errors.is_empty(), "{:?}", allowed.errors);
    assert_eq!(
        allowed.data.into_json().unwrap(),
        json!({"subject": "fixture-user"})
    );

    user.scopes.clear();
    let forbidden = schema.execute(Request::new("{ subject }").data(user)).await;
    assert_eq!(forbidden.errors.len(), 1);
    assert_eq!(
        forbidden.errors[0].extensions.as_ref().unwrap().get("code"),
        Some(&Value::from("FORBIDDEN"))
    );
}

#[test]
fn real_auth_response_sanitization() {
    let mut response = Response::new(Value::from_json(json!({
        "login": {"session": {"refreshToken": "fixture-secret", "refreshTokenExpiresAt": "2999-01-01T00:00:00Z"}}
    })).unwrap());
    let directive = graphql_refresh_cookie_directive(
        &mut response,
        &[GraphqlTopLevelField::with_response_key("signIn", "login")],
        &GraphqlRefreshCookieConfig::new(["signIn"], ["signOut"]),
    );
    assert!(
        matches!(directive, Some(GraphqlRefreshCookieDirective::Set { refresh_token, .. }) if refresh_token == "fixture-secret")
    );
    assert_eq!(
        response.data.into_json().unwrap()["login"]["session"]["refreshToken"],
        ""
    );
}
