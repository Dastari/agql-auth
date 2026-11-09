use async_graphql::{EmptyMutation, EmptySubscription, Object, Request, Schema};

use crate::prelude::*;

fn detailed_errors() -> Vec<AuthError> {
    let secret = "postgres://admin:hunter2@db.internal/auth".to_string();
    vec![
        AuthError::Store(secret.clone()),
        AuthError::PasswordHashing(secret.clone()),
        AuthError::TokenCreation(secret.clone()),
        AuthError::InvalidConfiguration(secret.clone()),
        AuthError::Config(secret.clone()),
        AuthError::OidcDiscovery(secret.clone()),
        AuthError::OidcTokenExchange(secret.clone()),
        AuthError::OidcCallback(secret.clone()),
        AuthError::OidcTokenValidation(secret.clone()),
        AuthError::InvalidOidcAuthorizationOptions(secret.clone()),
        AuthError::OAuthCallback(secret.clone()),
        AuthError::OAuthTokenExchange(secret.clone()),
        AuthError::OAuthUserInfo(secret.clone()),
        AuthError::ExternalLoginRejected(secret),
    ]
}

#[test]
fn display_is_the_safe_public_message_for_every_detailed_variant() {
    for err in detailed_errors() {
        let shown = err.to_string();
        assert_eq!(shown, err.public_message(), "{err:?}");
        assert!(!shown.contains("hunter2"), "{err:?}");
        assert!(err.internal_detail().unwrap().contains("hunter2"));
        assert!(format!("{err:?}").contains("hunter2"));
    }
    assert_eq!(
        AuthError::AuthThrottled {
            retry_after_seconds: 3
        }
        .to_string(),
        "rate limited"
    );
}

#[test]
fn diagnostic_keeps_internal_detail_for_logs() {
    let err = AuthError::Store("deadlock detected on refresh_tokens".to_string());
    assert_eq!(
        err.diagnostic().to_string(),
        "storage error: deadlock detected on refresh_tokens"
    );
    assert_eq!(
        format!("{:?}", err.diagnostic()),
        "storage error: deadlock detected on refresh_tokens"
    );
    assert_eq!(
        AuthError::InvalidCredentials.diagnostic().to_string(),
        "invalid credentials"
    );
    let boxed: Box<dyn std::error::Error> = Box::new(AuthError::Config("secret".into()));
    assert_eq!(boxed.to_string(), "invalid configuration");
}

struct LeakyQuery;

#[Object]
impl LeakyQuery {
    async fn plain_question_mark(&self) -> async_graphql::Result<bool> {
        Err(AuthError::Store(
            "postgres://admin:hunter2@db.internal/auth".to_string(),
        ))?;
        Ok(true)
    }
}

#[tokio::test]
async fn resolver_plain_question_mark_does_not_send_internal_detail() {
    let schema = Schema::build(LeakyQuery, EmptyMutation, EmptySubscription).finish();
    let response = schema.execute(Request::new("{ plainQuestionMark }")).await;
    assert_eq!(response.errors.len(), 1);
    let message = &response.errors[0].message;
    assert_eq!(message, "authentication service unavailable");
    assert!(!message.contains("hunter2"));
}
