use std::sync::Arc;

use async_trait::async_trait;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::{MemoryApiTokenStore, metadata};
use crate::AuthResult;
use crate::prelude::*;

fn request() -> ApiTokenIssueRequest {
    ApiTokenIssueRequest::new(
        "fixture token",
        "svc-fixture",
        ApiTokenPrincipalKind::service(),
        Duration::days(1),
    )
    .with_scopes(["fixture.read"])
}

/// Delegates to the memory store; touch fails on demand, and only the
/// required trait methods are implemented.
#[derive(Clone, Default)]
struct MinimalStore {
    inner: MemoryApiTokenStore,
    fail_touch: bool,
}

#[async_trait]
impl ApiTokenStore for MinimalStore {
    async fn insert_api_token(&self, token: StoredApiToken) -> AuthResult<()> {
        self.inner.insert_api_token(token).await
    }
    async fn find_api_token_by_hash(&self, hash: &str) -> AuthResult<Option<StoredApiToken>> {
        self.inner.find_api_token_by_hash(hash).await
    }
    async fn touch_api_token(
        &self,
        token_id: Uuid,
        used_at: OffsetDateTime,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> AuthResult<()> {
        if self.fail_touch {
            return Err(AuthError::Store("synthetic touch failure".into()));
        }
        self.inner
            .touch_api_token(token_id, used_at, ip_address, user_agent)
            .await
    }
    async fn revoke_api_token(
        &self,
        token_id: Uuid,
        revoked_at: OffsetDateTime,
        reason: ApiTokenRevocationReason,
    ) -> AuthResult<()> {
        self.inner
            .revoke_api_token(token_id, revoked_at, reason)
            .await
    }
}

#[tokio::test]
async fn audience_bound_token_is_refused_by_a_service_without_that_audience() {
    let store = MemoryApiTokenStore::default();
    let service = ApiTokenService::new(Arc::new(store.clone()));
    let bound = service
        .issue_token(request().with_audience("billing-api"))
        .await
        .unwrap();
    let error = service
        .authenticate_token(&bound.token, metadata())
        .await
        .unwrap_err();
    assert!(matches!(error, AuthError::InvalidApiToken), "{error:?}");
    assert!(
        store
            .get_by_raw_token(&bound.token)
            .unwrap()
            .last_used_at
            .is_none(),
        "a refused token must not be touched"
    );

    let unbound = service.issue_token(request()).await.unwrap();
    let principal = service
        .authenticate_token(&unbound.token, metadata())
        .await
        .unwrap();
    assert_eq!(principal.audience, None);
}

#[tokio::test]
async fn touch_failure_does_not_fail_authentication() {
    let store = MinimalStore {
        fail_touch: true,
        ..Default::default()
    };
    let service = ApiTokenService::new(Arc::new(store));
    let issued = service.issue_token(request()).await.unwrap();
    let principal = service
        .authenticate_bearer(&format!("Bearer {}", issued.token), metadata())
        .await
        .unwrap();
    assert_eq!(principal.token_id, issued.token_id);
}

#[tokio::test]
async fn default_bulk_revocation_is_an_explicit_error_not_a_silent_zero() {
    let store = MinimalStore::default();
    let now = OffsetDateTime::now_utc();
    assert!(matches!(
        store
            .revoke_api_tokens_for_principal(
                "svc-fixture",
                &ApiTokenPrincipalKind::service(),
                now,
                ApiTokenRevocationReason::PrincipalRevoked,
            )
            .await,
        Err(AuthError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        store
            .revoke_api_tokens_for_resource(
                "integration",
                "inventory",
                now,
                ApiTokenRevocationReason::ResourceRevoked,
            )
            .await,
        Err(AuthError::InvalidConfiguration(_))
    ));
}

#[tokio::test]
async fn expected_audience_refuses_other_and_unbound_tokens() {
    let store = MemoryApiTokenStore::default();
    let issuer = ApiTokenService::new(Arc::new(store.clone()));
    let service = ApiTokenService::new(Arc::new(store.clone()))
        .with_expected_audience("graphql-api")
        .unwrap();
    let ours = issuer
        .issue_token(request().with_audience("graphql-api"))
        .await
        .unwrap();
    let theirs = issuer
        .issue_token(request().with_audience("billing-api"))
        .await
        .unwrap();
    let unbound = issuer.issue_token(request()).await.unwrap();

    let principal = service
        .authenticate_token(&ours.token, metadata())
        .await
        .unwrap();
    assert_eq!(principal.audience.as_deref(), Some("graphql-api"));
    for token in [&theirs.token, &unbound.token] {
        assert!(matches!(
            service.authenticate_token(token, metadata()).await,
            Err(AuthError::InvalidApiToken)
        ));
    }
    // A foreign token is unknown here, even when it is revoked.
    issuer
        .revoke_token(theirs.token_id, ApiTokenRevocationReason::Manual)
        .await
        .unwrap();
    assert!(matches!(
        service.authenticate_token(&theirs.token, metadata()).await,
        Err(AuthError::InvalidApiToken)
    ));
    for audience in ["", " graphql-api", "graphql-api\n"] {
        assert!(matches!(
            ApiTokenService::new(Arc::new(store.clone())).with_expected_audience(audience),
            Err(AuthError::InvalidConfiguration(_))
        ));
    }
}

#[tokio::test]
async fn expected_resource_refuses_other_and_unbound_tokens() {
    let store = MemoryApiTokenStore::default();
    let issuer = ApiTokenService::new(Arc::new(store.clone()));
    let service = ApiTokenService::new(Arc::new(store.clone()))
        .with_expected_resource("integration", "inventory")
        .unwrap();
    let ours = issuer
        .issue_token(request().with_resource("integration", "inventory"))
        .await
        .unwrap();
    let other_id = issuer
        .issue_token(request().with_resource("integration", "billing"))
        .await
        .unwrap();
    let other_type = issuer
        .issue_token(request().with_resource("project", "inventory"))
        .await
        .unwrap();
    let unbound = issuer.issue_token(request()).await.unwrap();

    service
        .authenticate_token(&ours.token, metadata())
        .await
        .unwrap();
    for token in [&other_id.token, &other_type.token, &unbound.token] {
        assert!(matches!(
            service.authenticate_token(token, metadata()).await,
            Err(AuthError::InvalidApiToken)
        ));
    }
    // Without a configured resource, the binding is carried for the host to enforce.
    let carried = issuer
        .authenticate_token(&other_id.token, metadata())
        .await
        .unwrap();
    assert_eq!(carried.resource_id.as_deref(), Some("billing"));
}

#[tokio::test]
async fn issuance_refuses_blank_audience_and_partial_resource_bindings() {
    let service = ApiTokenService::new(Arc::new(MemoryApiTokenStore::default()));
    let mut blank_audience = request();
    blank_audience.audience = Some(" ".into());
    let mut type_only = request();
    type_only.resource_type = Some("integration".into());
    let mut id_only = request();
    id_only.resource_id = Some("inventory".into());
    for request in [blank_audience, type_only, id_only] {
        assert!(matches!(
            service.issue_token(request).await,
            Err(AuthError::InvalidConfiguration(_))
        ));
    }
}

#[derive(Default)]
struct RecordingObserver(std::sync::Mutex<Vec<(Uuid, &'static str)>>);

#[async_trait]
impl ApiTokenTouchObserver for RecordingObserver {
    async fn api_token_touch_failed(&self, token_id: Uuid, error: &AuthError) {
        self.0.lock().unwrap().push((token_id, error.public_code()));
    }
}

#[tokio::test]
async fn touch_failure_is_reported_to_the_observer() {
    let observer = Arc::new(RecordingObserver::default());
    let service = ApiTokenService::new(Arc::new(MinimalStore {
        fail_touch: true,
        ..Default::default()
    }))
    .with_touch_observer(observer.clone());
    let issued = service.issue_token(request()).await.unwrap();
    service
        .authenticate_token(&issued.token, metadata())
        .await
        .unwrap();
    assert_eq!(
        *observer.0.lock().unwrap(),
        vec![(issued.token_id, "AUTH_SERVICE_UNAVAILABLE")]
    );

    let healthy = ApiTokenService::new(Arc::new(MinimalStore::default()))
        .with_touch_observer(observer.clone());
    let issued = healthy.issue_token(request()).await.unwrap();
    healthy
        .authenticate_token(&issued.token, metadata())
        .await
        .unwrap();
    assert_eq!(observer.0.lock().unwrap().len(), 1);
}
