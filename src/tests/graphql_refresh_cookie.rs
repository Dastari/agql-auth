//! The refresh-cookie helper never leaves a raw refresh token in the body.
use async_graphql::{Response, ServerError, Value};
use serde_json::{Value as JsonValue, json};

use crate::prelude::*;

/// Shaped like a token from `AuthService`: 48 random bytes, base64url.
const TOKEN: &str = "Zm9vYmFyLXJlZnJlc2gtdG9rZW4tc2hhcGVkLWxpa2UtdGhlLXJlYWwtb25lLW9r";
const EXPIRES: &str = "2999-01-01T00:00:00Z";

fn config() -> GraphqlRefreshCookieConfig {
    GraphqlRefreshCookieConfig::new(["authLogin", "authRefreshSession"], ["authLogout"])
}

fn response(data: JsonValue) -> Response {
    Response::new(Value::from_json(data).unwrap())
}

fn login(key: &str) -> [GraphqlTopLevelField; 1] {
    [GraphqlTopLevelField::with_response_key("authLogin", key)]
}

fn set() -> Option<GraphqlRefreshCookieDirective> {
    Some(GraphqlRefreshCookieDirective::Set {
        refresh_token: TOKEN.to_string(),
        refresh_token_expires_at: EXPIRES.to_string(),
    })
}

/// Asserts that no string in the response body still holds the token.
fn assert_scrubbed(response: Response) {
    let body = serde_json::to_string(&response.data.into_json().unwrap()).unwrap();
    assert!(!body.contains(TOKEN), "refresh token left in body: {body}");
}

#[test]
fn a_partial_error_does_not_leave_the_token_in_the_body() {
    let mut response = response(json!({
        "login": {"session": {"refreshToken": TOKEN, "refreshTokenExpiresAt": EXPIRES}},
        "other": null
    }));
    response
        .errors
        .push(ServerError::new("other field failed", None));
    let directive = graphql_refresh_cookie_directive(&mut response, &login("login"), &config());
    assert_eq!(
        directive,
        set(),
        "the session was issued, so set the cookie"
    );
    assert_scrubbed(response);
}

#[test]
fn an_omitted_expiry_does_not_leave_the_token_in_the_body() {
    let mut response = response(json!({
        "login": {"session": {"refreshToken": TOKEN}}
    }));
    let directive = graphql_refresh_cookie_directive(&mut response, &login("login"), &config());
    assert_eq!(directive, None, "no expiry, no cookie");
    assert_scrubbed(response);
}

#[test]
fn an_aliased_session_does_not_leave_the_token_in_the_body() {
    let mut response = response(json!({
        "login": {"s": {"refreshToken": TOKEN, "refreshTokenExpiresAt": EXPIRES}}
    }));
    graphql_refresh_cookie_directive(&mut response, &login("login"), &config());
    assert_scrubbed(response);
}

#[test]
fn a_second_aliased_copy_of_the_token_is_scrubbed_too() {
    let mut response = response(json!({
        "login": {
            "session": {"refreshToken": TOKEN, "refreshTokenExpiresAt": EXPIRES, "copy": TOKEN},
            "nested": [{"deep": {"again": TOKEN}}]
        },
        "echo": TOKEN
    }));
    let directive = graphql_refresh_cookie_directive(&mut response, &login("login"), &config());
    assert_eq!(directive, set());
    assert_scrubbed(response);
}

#[test]
fn an_aliased_token_field_alone_is_scrubbed() {
    for data in [
        json!({"login": {"session": {"rt": TOKEN, "refreshTokenExpiresAt": EXPIRES}}}),
        json!({"login": {"s": {"rt": TOKEN}}}),
        json!({"login": [{"session": {"rt": TOKEN}}]}),
    ] {
        let mut response = response(data);
        graphql_refresh_cookie_directive(&mut response, &login("login"), &config());
        assert_scrubbed(response);
    }
}

#[test]
fn scanning_without_response_keys_finds_a_later_entry() {
    let mut response = response(json!({
        "first": {"success": true},
        "second": {"session": {"refreshToken": TOKEN, "refreshTokenExpiresAt": EXPIRES}}
    }));
    let directive = graphql_refresh_cookie_directive(
        &mut response,
        &[GraphqlTopLevelField::new("authLogin")],
        &config(),
    );
    assert_eq!(directive, set());
    assert_scrubbed(response);
}

#[test]
fn several_issuing_entries_are_all_scrubbed() {
    let other = "b3RoZXItcmVmcmVzaC10b2tlbi1zaGFwZWQtbGlrZS10aGUtcmVhbC1vbmUtb2sA";
    let mut response = response(json!({
        "a": {"session": {"refreshToken": TOKEN, "refreshTokenExpiresAt": EXPIRES}},
        "b": {"session": {"refreshToken": other, "refreshTokenExpiresAt": EXPIRES}}
    }));
    let fields = [
        GraphqlTopLevelField::with_response_key("authLogin", "a"),
        GraphqlTopLevelField::with_response_key("authLogin", "b"),
    ];
    graphql_refresh_cookie_directive(&mut response, &fields, &config());
    let body = serde_json::to_string(&response.data.into_json().unwrap()).unwrap();
    assert!(!body.contains(TOKEN) && !body.contains(other), "{body}");
}

#[test]
fn errors_without_data_return_nothing() {
    let mut response = Response::from_errors(vec![ServerError::new("failed", None)]);
    let directive = graphql_refresh_cookie_directive(&mut response, &login("login"), &config());
    assert_eq!(directive, None);
}

#[test]
fn a_clearing_field_with_errors_does_not_clear() {
    let mut response = response(json!({"logout": null}));
    response.errors.push(ServerError::new("failed", None));
    let fields = [GraphqlTopLevelField::with_response_key(
        "authLogout",
        "logout",
    )];
    assert_eq!(
        graphql_refresh_cookie_directive(&mut response, &fields, &config()),
        None
    );
}

#[test]
fn unrelated_fields_and_values_are_left_alone() {
    let mut response = response(json!({
        "login": {
            "session": {"refreshToken": TOKEN, "refreshTokenExpiresAt": EXPIRES,
                        "accessToken": "header.payload.signature"},
            "user": {"id": "user-1"}
        },
        "digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }));
    graphql_refresh_cookie_directive(&mut response, &login("login"), &config());
    let data = response.data.into_json().unwrap();
    assert_eq!(data["login"]["session"]["refreshToken"], "");
    assert_eq!(
        data["login"]["session"]["accessToken"],
        "header.payload.signature"
    );
    assert_eq!(data["login"]["user"]["id"], "user-1");
    assert_eq!(
        data["digest"],
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn opting_out_of_sanitizing_keeps_the_body() {
    let mut config = config();
    config.sanitize_response = false;
    let mut response = response(json!({
        "login": {"session": {"refreshToken": TOKEN, "refreshTokenExpiresAt": EXPIRES}}
    }));
    let directive = graphql_refresh_cookie_directive(&mut response, &login("login"), &config);
    assert_eq!(directive, set());
    assert_eq!(
        response.data.into_json().unwrap()["login"]["session"]["refreshToken"],
        TOKEN
    );
}

#[test]
fn every_issued_refresh_token_has_the_scrubbed_shape() {
    for _ in 0..256 {
        assert!(crate::util::is_opaque_token_shape(
            &crate::util::generate_opaque_token()
        ));
    }
    assert!(crate::util::is_opaque_token_shape(TOKEN));
}

#[test]
fn sanitizing_keeps_selection_order_and_unrelated_digests() {
    const DIGEST: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    // Built directly, so the order is the selection order, not alphabetical.
    let mut response = Response::new(async_graphql::value!({
        "zeta": {"digest": DIGEST},
        "authLogin": {
            "user": {"avatarSha256": DIGEST},
            "session": {"refreshTokenExpiresAt": EXPIRES, "refreshToken": TOKEN},
        },
        "alpha": 1,
    }));
    let selected = [
        GraphqlTopLevelField::new("zeta"),
        GraphqlTopLevelField::new("authLogin"),
        GraphqlTopLevelField::new("alpha"),
    ];
    let directive = graphql_refresh_cookie_directive(&mut response, &selected, &config());
    assert_eq!(directive, set());

    let Value::Object(top) = &response.data else {
        panic!("object body");
    };
    let keys: Vec<&str> = top.keys().map(|key| key.as_str()).collect();
    assert_eq!(keys, ["zeta", "authLogin", "alpha"], "selection order kept");
    let Value::Object(login) = &top["authLogin"] else {
        panic!("login object");
    };
    let Value::Object(session) = &login["session"] else {
        panic!("session object");
    };
    let session_keys: Vec<&str> = session.keys().map(|key| key.as_str()).collect();
    assert_eq!(session_keys, ["refreshTokenExpiresAt", "refreshToken"]);

    let body = serde_json::to_string(&response.data.into_json().unwrap()).unwrap();
    assert!(!body.contains(TOKEN), "refresh token left in body: {body}");
    assert_eq!(
        body.matches(DIGEST).count(),
        2,
        "hex digests are not refresh tokens: {body}"
    );
}
