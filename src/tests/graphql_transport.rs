use async_graphql::{Response, ServerError, Value};
use serde_json::json;

use crate::prelude::*;

#[test]
fn refresh_cookie_directive_uses_schema_field_and_alias_response_key() {
    let mut response = auth_session_response("CustomLoginAlias", "refresh-secret");
    let fields = [GraphqlTopLevelField::with_response_key(
        "authLogin",
        "CustomLoginAlias",
    )];

    let directive = graphql_refresh_cookie_directive(&mut response, &fields, &config());

    assert_eq!(
        directive,
        Some(GraphqlRefreshCookieDirective::Set {
            refresh_token: "refresh-secret".to_string(),
            refresh_token_expires_at: "2999-01-01T00:00:00Z".to_string(),
        })
    );
    let data = response.data.into_json().expect("response json");
    assert_eq!(data["CustomLoginAlias"]["session"]["refreshToken"], "");
}

#[test]
fn refresh_cookie_directive_ignores_non_auth_schema_fields() {
    let mut response = auth_session_response("LooksLikeAuth", "refresh-secret");
    let fields = [GraphqlTopLevelField::with_response_key(
        "authCurrentUser",
        "LooksLikeAuth",
    )];

    let directive = graphql_refresh_cookie_directive(&mut response, &fields, &config());

    assert_eq!(directive, None);
    let data = response.data.into_json().expect("response json");
    assert_eq!(
        data["LooksLikeAuth"]["session"]["refreshToken"],
        "refresh-secret"
    );
}

#[test]
fn refresh_cookie_directive_can_scan_without_response_keys() {
    let mut response = auth_session_response("AnyAlias", "refresh-secret");
    let fields = [GraphqlTopLevelField::new("authRefreshSession")];

    let directive = graphql_refresh_cookie_directive(&mut response, &fields, &config());

    assert!(matches!(
        directive,
        Some(GraphqlRefreshCookieDirective::Set { .. })
    ));
    let data = response.data.into_json().expect("response json");
    assert_eq!(data["AnyAlias"]["session"]["refreshToken"], "");
}

#[test]
fn refresh_cookie_directive_clears_on_logout_schema_fields() {
    let mut response = Response::new(
        Value::from_json(json!({
            "RenamedLogout": {
                "success": true,
                "error": null
            }
        }))
        .expect("response value"),
    );
    let fields = [GraphqlTopLevelField::with_response_key(
        "authLogoutAllSessions",
        "RenamedLogout",
    )];

    let directive = graphql_refresh_cookie_directive(&mut response, &fields, &config());

    assert_eq!(directive, Some(GraphqlRefreshCookieDirective::Clear));
}

#[test]
fn refresh_cookie_directive_returns_none_when_response_has_errors() {
    let mut response = Response::from_errors(vec![ServerError::new("failed", None)]);
    let fields = [GraphqlTopLevelField::new("authLogin")];

    let directive = graphql_refresh_cookie_directive(&mut response, &fields, &config());

    assert_eq!(directive, None);
}

fn config() -> GraphqlRefreshCookieConfig {
    GraphqlRefreshCookieConfig::new(
        ["authLogin", "authLoginWithCode", "authRefreshSession"],
        ["authLogout", "authLogoutAllSessions"],
    )
}

fn auth_session_response(alias: &str, refresh_token: &str) -> Response {
    Response::new(
        Value::from_json(json!({
            alias: {
                "success": true,
                "error": null,
                "session": {
                    "accessToken": "access-token",
                    "accessTokenExpiresAt": "2999-01-01T00:00:00Z",
                    "refreshToken": refresh_token,
                    "refreshTokenExpiresAt": "2999-01-01T00:00:00Z",
                    "user": {
                        "id": "user-1",
                        "principal": "owner@example.com"
                    }
                }
            }
        }))
        .expect("response value"),
    )
}
