//! Run: cargo run --locked --example password-login-rejection
//! No production schema or routes: stores below are deliberately test-only.
use std::sync::Arc;

use agql_auth::AuthResult;
use agql_auth::prelude::*;
use async_trait::async_trait;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

struct Users(Vec<StoredUser>);
#[async_trait]
impl UserStore for Users {
    async fn find_user_by_principal(&self, principal: &str) -> AuthResult<Option<StoredUser>> {
        Ok(self.0.iter().find(|u| u.principal == principal).cloned())
    }
    async fn find_user_by_id(&self, id: &str) -> AuthResult<Option<StoredUser>> {
        Ok(self.0.iter().find(|u| u.id == id).cloned())
    }
}

// Any refresh-store access makes this rejection-only example fail immediately.
struct NoSessions;
#[async_trait]
impl RefreshTokenStore for NoSessions {
    async fn insert_refresh_token(&self, _: StoredRefreshToken) -> AuthResult<()> {
        panic!("unexpected session issuance")
    }
    async fn find_refresh_token_by_hash(&self, _: &str) -> AuthResult<Option<StoredRefreshToken>> {
        panic!("unexpected refresh lookup")
    }
    async fn revoke_refresh_token(
        &self,
        _: Uuid,
        _: OffsetDateTime,
        _: Option<Uuid>,
        _: RefreshTokenRevocationReason,
    ) -> AuthResult<()> {
        panic!("unexpected revocation")
    }
    async fn revoke_refresh_token_family(
        &self,
        _: Uuid,
        _: OffsetDateTime,
        _: RefreshTokenRevocationReason,
    ) -> AuthResult<()> {
        panic!("unexpected family revocation")
    }
    async fn touch_refresh_token(
        &self,
        _: Uuid,
        _: OffsetDateTime,
        _: Option<String>,
        _: Option<String>,
    ) -> AuthResult<()> {
        panic!("unexpected refresh use")
    }
    async fn rotate_refresh_token(
        &self,
        _: Uuid,
        _: StoredRefreshToken,
        _: OffsetDateTime,
        _: Option<String>,
        _: Option<String>,
    ) -> AuthResult<bool> {
        panic!("unexpected rotation")
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AuthConfig::new("example-secret-at-least-thirty-two-bytes");
    config.rate_limits.credential = AuthRateLimitPolicy {
        enabled: true,
        window: Duration::minutes(15),
        backoff_after_attempts: 1,
        max_attempts_before_lockout: 2,
        base_backoff: Duration::ZERO,
        max_backoff: Duration::ZERO,
        lockout_duration: Duration::minutes(5),
        state_ttl: Duration::hours(1),
    };
    let hasher = AuthService::new(
        config.clone(),
        Arc::new(Users(vec![])),
        Arc::new(NoSessions),
    )?;
    let hash = hasher.hash_password("correct")?;
    let users = [false, true]
        .into_iter()
        .map(|disabled| {
            let id = if disabled { "disabled" } else { "enabled" };
            StoredUser {
                id: id.into(),
                principal: format!("{id}@example.com"),
                password_hash: hash.clone(),
                roles: vec![],
                scopes: vec![],
                disabled,
            }
        })
        .collect();
    let auth = AuthService::new_with_rate_limit_store_and_clock(
        config,
        Arc::new(Users(users)),
        Arc::new(NoSessions),
        Arc::new(MemoryAuthRateLimitStore::default()),
        Arc::new(FixedClock::new(OffsetDateTime::UNIX_EPOCH)),
    )?;
    for (index, (case, password)) in [
        ("unknown", "wrong"),
        ("enabled", "wrong"),
        ("disabled", "correct"),
    ]
    .into_iter()
    .enumerate()
    {
        let metadata = ClientMetadata {
            ip_address: Some(format!("192.0.2.{}", index + 1)),
            ..Default::default()
        };
        for attempt in 1..=3 {
            let error = auth
                .login(&format!("{case}@example.com"), password, metadata.clone())
                .await
                .unwrap_err();
            if attempt == 3 {
                assert!(matches!(
                    error,
                    AuthError::AuthLocked {
                        retry_after_seconds: 300
                    }
                ));
            } else if case == "disabled" {
                assert!(matches!(error, AuthError::UserDisabled));
            } else {
                assert!(matches!(error, AuthError::InvalidCredentials));
            }
            println!(
                "{case} attempt {attempt}: {} ({})",
                error.public_message(),
                error.public_code()
            );
        }
    }
    Ok(())
}
