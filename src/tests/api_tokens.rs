use std::sync::Arc;

use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Request, Schema};
use time::{Duration, OffsetDateTime};

use super::{MemoryApiTokenStore, metadata};
use crate::prelude::*;
use crate::util::hash_api_token;

struct PrincipalQuery;

#[Object]
impl PrincipalQuery {
    #[graphql(guard = "RequirePrincipalScope::new(\"service.write\")")]
    async fn principal_subject(&self, ctx: &Context<'_>) -> async_graphql::Result<String> {
        Ok(principal_from_ctx(ctx)?.subject().to_string())
    }
}

fn issue_request() -> ApiTokenIssueRequest {
    ApiTokenIssueRequest::new(
        "inventory sync",
        "svc-inventory",
        ApiTokenPrincipalKind::service(),
        Duration::days(365),
    )
    .with_scopes(["service.read", "service.write"])
    .with_audience("graphql-api")
    .with_resource("integration", "inventory")
    .with_metadata(metadata())
}

#[tokio::test]
async fn issuing_api_token_stores_hash_and_returns_raw_token_once() {
    let store = MemoryApiTokenStore::default();
    let service = ApiTokenService::new(Arc::new(store.clone()));

    let issued = service.issue_token(issue_request()).await.unwrap();

    assert_eq!(issued.display_name, "inventory sync");
    assert_eq!(issued.subject, "svc-inventory");
    assert_eq!(issued.principal_kind, ApiTokenPrincipalKind::service());
    assert!(issued.token.starts_with(DEFAULT_API_TOKEN_PREFIX));
    assert!(!issued.token.contains('.'));

    let stored = store.get_by_raw_token(&issued.token).unwrap();
    assert_eq!(stored.id, issued.token_id);
    assert_eq!(stored.token_hash, hash_api_token(&issued.token));
    assert_ne!(stored.token_hash, issued.token);
    assert_eq!(stored.subject, "svc-inventory");
    assert_eq!(stored.scopes, vec!["service.read", "service.write"]);
    assert_eq!(stored.audience.as_deref(), Some("graphql-api"));
    assert_eq!(stored.resource_type.as_deref(), Some("integration"));
    assert_eq!(stored.resource_id.as_deref(), Some("inventory"));
    assert!(stored.last_used_at.is_none());
    assert!(stored.revoked_at.is_none());

    let debug = format!("{issued:?}");
    assert!(!debug.contains(&issued.token));
    assert!(debug.contains("inventory sync"));
    assert!(debug.contains("svc-inventory"));
}

#[tokio::test]
async fn authenticating_api_token_returns_principal_and_updates_last_used() {
    let store = MemoryApiTokenStore::default();
    let service = ApiTokenService::new(Arc::new(store.clone()));
    let issued = service.issue_token(issue_request()).await.unwrap();

    let principal = service
        .authenticate_bearer(
            &format!("Bearer {}", issued.token),
            ClientMetadata {
                ip_address: Some("10.0.0.10".to_string()),
                user_agent: Some("service-client".to_string()),
            },
        )
        .await
        .unwrap();

    assert_eq!(principal.token_id, issued.token_id);
    assert_eq!(principal.subject, "svc-inventory");
    assert_eq!(principal.principal_kind, ApiTokenPrincipalKind::service());
    assert_eq!(principal.scopes, vec!["service.read", "service.write"]);
    assert_eq!(principal.audience.as_deref(), Some("graphql-api"));
    assert_eq!(principal.resource_type.as_deref(), Some("integration"));
    assert_eq!(principal.resource_id.as_deref(), Some("inventory"));
    assert!(principal.has_scope("service.write"));
    assert!(principal.has_any_scope(&["service.delete", "service.read"]));
    assert!(principal.has_all_scopes(&["service.read", "service.write"]));

    let stored = store.get_by_raw_token(&issued.token).unwrap();
    assert!(stored.last_used_at.is_some());
    assert_eq!(stored.ip_address.as_deref(), Some("10.0.0.10"));
    assert_eq!(stored.user_agent.as_deref(), Some("service-client"));
}

#[tokio::test]
async fn expired_api_token_is_rejected() {
    let store = MemoryApiTokenStore::default();
    let service = ApiTokenService::new(Arc::new(store.clone()));
    let issued = service.issue_token(issue_request()).await.unwrap();
    store
        .tokens_by_id
        .lock()
        .unwrap()
        .get_mut(&issued.token_id)
        .unwrap()
        .expires_at = OffsetDateTime::now_utc() - Duration::seconds(1);

    let err = service
        .authenticate_bearer(&issued.token, metadata())
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::ApiTokenExpired));
}

#[tokio::test]
async fn revoked_api_token_is_rejected() {
    let store = MemoryApiTokenStore::default();
    let service = ApiTokenService::new(Arc::new(store));
    let issued = service.issue_token(issue_request()).await.unwrap();

    service
        .revoke_token(issued.token_id, ApiTokenRevocationReason::Manual)
        .await
        .unwrap();

    let err = service
        .authenticate_bearer(&issued.token, metadata())
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::ApiTokenRevoked));
}

#[tokio::test]
async fn auth_principal_helpers_support_user_and_api_token_principals() {
    let api = ApiTokenPrincipal {
        token_id: uuid::Uuid::new_v4(),
        subject: "svc-inventory".to_string(),
        principal_kind: ApiTokenPrincipalKind::integration(),
        scopes: vec!["service.read".to_string()],
        audience: Some("graphql-api".to_string()),
        resource_type: Some("integration".to_string()),
        resource_id: Some("inventory".to_string()),
        expires_at: OffsetDateTime::now_utc() + Duration::days(1),
    };

    let principal = AuthPrincipal::ApiToken(api.clone());
    assert_eq!(principal.subject(), "svc-inventory");
    assert!(principal.roles().is_empty());
    assert_eq!(principal.scopes(), &["service.read".to_string()]);
    assert!(principal.has_scope("service.read"));
    assert_eq!(principal.audience(), Some("graphql-api"));
    assert_eq!(principal.resource_type(), Some("integration"));
    assert_eq!(principal.resource_id(), Some("inventory"));
    assert_eq!(principal.token_id(), Some(api.token_id));
    assert_eq!(
        principal
            .principal_kind()
            .map(ApiTokenPrincipalKind::as_str),
        Some("integration")
    );
    assert!(principal.as_api_token().is_some());
    assert!(principal.as_user().is_none());
}

#[tokio::test]
async fn api_token_service_can_inject_principal_for_graphql_guards() {
    let store = MemoryApiTokenStore::default();
    let service = ApiTokenService::new(Arc::new(store));
    let issued = service.issue_token(issue_request()).await.unwrap();
    let schema = Schema::build(PrincipalQuery, EmptyMutation, EmptySubscription).finish();
    let request = service
        .inject_http_auth(
            Request::new("{ principalSubject }"),
            Some(&format!("Bearer {}", issued.token)),
            metadata(),
        )
        .await
        .unwrap();

    let response = schema.execute(request).await;
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap()["principalSubject"],
        "svc-inventory"
    );
}
