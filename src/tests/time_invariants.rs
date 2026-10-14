use super::*;
use time::Duration;

#[test]
fn service_rejects_invalid_identity_and_lifetimes_at_construction() {
    for field in ["issuer", "audience"] {
        let mut config = AuthConfig::new(TEST_HS256_SECRET);
        if field == "issuer" {
            config.issuer = " \t".into();
        } else {
            config.audience = "".into();
        }
        assert!(matches!(
            AuthService::new(
                config,
                Arc::new(MemoryUserStore::default()),
                Arc::new(MemoryRefreshTokenStore::default())
            ),
            Err(AuthError::InvalidConfiguration(_))
        ));
    }
    for ttl in [Duration::ZERO, Duration::seconds(-1), Duration::MAX] {
        for field in ["access", "maximum", "refresh"] {
            let mut config = AuthConfig::new(TEST_HS256_SECRET);
            match field {
                "access" => config.access_token_ttl = ttl,
                "maximum" => config.max_access_token_ttl = ttl,
                _ => config.refresh_token_ttl = ttl,
            }
            assert!(
                matches!(
                    AuthService::new(
                        config,
                        Arc::new(MemoryUserStore::default()),
                        Arc::new(MemoryRefreshTokenStore::default())
                    ),
                    Err(AuthError::InvalidConfiguration(_))
                ),
                "{field}: {ttl}"
            );
        }
    }
    // The existing custom-grant ceiling is deliberately not silently redefined
    // as a limit on separately configured ordinary refreshable sessions.
    let mut config = AuthConfig::new(TEST_HS256_SECRET);
    config.access_token_ttl = Duration::days(2);
    assert!(
        AuthService::new(
            config,
            Arc::new(MemoryUserStore::default()),
            Arc::new(MemoryRefreshTokenStore::default())
        )
        .is_ok()
    );
}

#[tokio::test]
async fn impossible_expiries_fail_before_credential_storage() {
    let auth = test_auth_service(Default::default(), Default::default());
    let api_store = MemoryApiTokenStore::default();
    let api = ApiTokenService::new(Arc::new(api_store.clone()));
    let challenge_store = MemoryLoginChallengeStore::default();
    assert!(matches!(
        api.issue_token(ApiTokenIssueRequest::new(
            "fixture",
            "fixture",
            ApiTokenPrincipalKind::service(),
            Duration::MAX
        ))
        .await,
        Err(AuthError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        auth.create_login_challenge(
            &challenge_store,
            "synthetic@example.invalid",
            LoginChallengeOptions {
                ttl: Duration::MAX,
                ..Default::default()
            }
        )
        .await,
        Err(AuthError::InvalidConfiguration(_))
    ));
    assert!(challenge_store.challenges.lock().unwrap().is_empty());
    assert!(api_store.tokens_by_id.lock().unwrap().is_empty());
    assert!(matches!(
        auth.issue_purpose_token(PurposeTokenIssueRequest::new(
            "fixture",
            "fixture-purpose",
            "fixture-audience",
            Duration::MAX
        )),
        Err(AuthError::InvalidConfiguration(_))
    ));
    for ttl in [Duration::ZERO, Duration::seconds(-1), Duration::MAX] {
        assert!(matches!(
            auth.issue_password_reset_token_with_ttl("fixture", ttl),
            Err(AuthError::InvalidConfiguration(_))
        ));
    }
}

#[test]
fn invalid_or_overflowing_reauthorization_schedule_requires_an_immediate_check() {
    let now = OffsetDateTime::UNIX_EPOCH;
    for policy in [
        ReauthorizationPolicy {
            min_interval: Duration::MAX,
            ..Default::default()
        },
        ReauthorizationPolicy {
            min_interval: Duration::seconds(-1),
            ..Default::default()
        },
        ReauthorizationPolicy {
            lifetime_fraction: f64::NAN,
            ..Default::default()
        },
        ReauthorizationPolicy {
            max_connection_ttl: Some(Duration::MAX),
            ..Default::default()
        },
        ReauthorizationPolicy {
            max_connection_ttl: Some(Duration::seconds(-1)),
            ..Default::default()
        },
    ] {
        assert_eq!(
            policy.next_deadline(now, &AccessTokenMetadata::default(), now),
            now
        );
    }
    assert!(crate::util::checked_jwt_expiry(now, Duration::nanoseconds(1), "fixture").is_err());
    // Fractional TTLs remain valid when they cross into a future JWT second.
    let late_in_second = now + Duration::milliseconds(900);
    assert_eq!(
        crate::util::checked_jwt_expiry(late_in_second, Duration::milliseconds(200), "fixture")
            .unwrap()
            .unix_timestamp(),
        1
    );

    assert!(crate::util::checked_expiry(now, Duration::MAX, "fixture").is_err());
}
