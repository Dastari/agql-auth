use std::sync::Arc;

use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Request, Schema};
use time::Duration;

use super::jwt_signing::RSA_PUBLIC_KEY_A;
use super::validator::rs256_config;
use super::{MemoryApiTokenStore, MemoryRefreshTokenStore, MemoryUserStore, metadata};
use crate::prelude::*;

struct CombinedQuery;

#[Object]
impl CombinedQuery {
    async fn principal_subject(&self, ctx: &Context<'_>) -> async_graphql::Result<String> {
        Ok(principal_from_ctx(ctx)?.subject().to_string())
    }

    #[graphql(guard = "RequirePrincipalScope::new(\"shared.read\")")]
    async fn guarded_subject(&self, ctx: &Context<'_>) -> async_graphql::Result<String> {
        Ok(principal_from_ctx(ctx)?.subject().to_string())
    }
}

#[tokio::test]
async fn combined_auth_injects_user_jwt_principal() {
    let auth = auth_service(rs256_config());
    let payload = auth
        .issue_verified_user_session_with_scopes(
            "user-1",
            vec![],
            vec!["shared.read".to_string()],
            AuthMethod::Password,
            metadata(),
        )
        .await
        .unwrap();
    let validator = validator();
    let api_tokens = ApiTokenService::new(Arc::new(MemoryApiTokenStore::default()));
    let combined = CombinedAuth::new(&validator, &api_tokens);
    let schema = Schema::build(CombinedQuery, EmptyMutation, EmptySubscription).finish();

    let request = combined
        .inject_http_auth(
            Request::new("{ principalSubject guardedSubject }"),
            Some(&format!("Bearer {}", payload.access_token)),
            metadata(),
        )
        .await
        .unwrap();
    let response = schema.execute(request).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    assert_eq!(data["principalSubject"], "user-1");
    assert_eq!(data["guardedSubject"], "user-1");
}

#[tokio::test]
async fn combined_auth_injects_api_token_principal() {
    let validator = validator();
    let api_store = MemoryApiTokenStore::default();
    let api_tokens = ApiTokenService::new(Arc::new(api_store));
    let issued = api_tokens.issue_token(api_request()).await.unwrap();
    let combined = CombinedAuth::new(&validator, &api_tokens);
    let schema = Schema::build(CombinedQuery, EmptyMutation, EmptySubscription).finish();

    let request = combined
        .inject_http_auth(
            Request::new("{ principalSubject guardedSubject }"),
            Some(&format!("Bearer {}", issued.token)),
            metadata(),
        )
        .await
        .unwrap();
    let response = schema.execute(request).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let data = response.data.into_json().unwrap();
    assert_eq!(data["principalSubject"], "svc-sync");
    assert_eq!(data["guardedSubject"], "svc-sync");
}

#[tokio::test]
async fn combined_auth_missing_header_leaves_request_unauthenticated() {
    let validator = validator();
    let api_tokens = ApiTokenService::new(Arc::new(MemoryApiTokenStore::default()));
    let combined = CombinedAuth::new(&validator, &api_tokens);
    let schema = Schema::build(CombinedQuery, EmptyMutation, EmptySubscription).finish();

    let request = combined
        .inject_http_auth(Request::new("{ principalSubject }"), None, metadata())
        .await
        .unwrap();
    let response = schema.execute(request).await;

    assert_eq!(response.errors.len(), 1);
}

#[tokio::test]
async fn combined_auth_does_not_fall_back_for_expired_jwt() {
    let mut config = rs256_config();
    config.access_token_ttl = Duration::seconds(-5);
    let auth = auth_service(config);
    let payload = auth
        .issue_verified_user_session("user-1", vec![], AuthMethod::Password, metadata())
        .await
        .unwrap();
    let validator = validator();
    let api_tokens = ApiTokenService::new(Arc::new(MemoryApiTokenStore::default()));
    let combined = CombinedAuth::new(&validator, &api_tokens);

    let err = combined
        .inject_http_auth(
            Request::new("{ principalSubject }"),
            Some(&format!("Bearer {}", payload.access_token)),
            metadata(),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, AuthError::AccessTokenExpired));
}

#[tokio::test]
async fn combined_auth_rejects_malformed_jwt_that_is_not_api_token() {
    let validator = validator();
    let api_tokens = ApiTokenService::new(Arc::new(MemoryApiTokenStore::default()));
    let combined = CombinedAuth::new(&validator, &api_tokens);

    let err = combined
        .inject_http_auth(
            Request::new("{ principalSubject }"),
            Some("Bearer not.a.jwt"),
            metadata(),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, AuthError::InvalidAccessToken));
}

fn auth_service(config: AuthConfig) -> AuthService<MemoryUserStore, MemoryRefreshTokenStore> {
    AuthService::new(
        config,
        Arc::new(MemoryUserStore::default()),
        Arc::new(MemoryRefreshTokenStore::default()),
    )
    .unwrap()
}

fn validator() -> AccessTokenValidator {
    AccessTokenValidator::builder()
        .issuer("agql-auth")
        .audience("agql-auth-clients")
        .rs256_public_pem(RSA_PUBLIC_KEY_A)
        .key_id("auth-key-1")
        .build()
        .unwrap()
}

fn api_request() -> ApiTokenIssueRequest {
    ApiTokenIssueRequest::new(
        "sync service",
        "svc-sync",
        ApiTokenPrincipalKind::service(),
        Duration::days(30),
    )
    .with_scopes(["shared.read"])
    .with_metadata(metadata())
}
