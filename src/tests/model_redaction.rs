use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::prelude::*;

const SECRET: &str = "synthetic-secret-sentinel";

fn assert_redacted(rendered: String) {
    assert!(
        !rendered.contains(SECRET),
        "Debug output leaked secret material: {rendered}"
    );
    assert!(rendered.contains("[redacted]"), "{rendered}");
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

#[test]
fn stored_credential_records_redact_hashes_in_debug() {
    let api = StoredApiToken {
        id: Uuid::new_v4(),
        token_hash: SECRET.into(),
        display_name: "display".into(),
        subject: "svc".into(),
        principal_kind: ApiTokenPrincipalKind::service(),
        scopes: vec!["scope.read".into()],
        audience: Some("api".into()),
        resource_type: None,
        resource_id: None,
        created_at: now(),
        expires_at: now() + Duration::days(1),
        last_used_at: None,
        revoked_at: None,
        user_agent: None,
        ip_address: None,
    };
    let rendered = format!("{api:?}");
    assert!(rendered.contains("scope.read") && rendered.contains("svc"));
    assert_redacted(rendered);
    assert_redacted(format!("{api:#?}"));

    let user = StoredUser {
        id: "user-1".into(),
        principal: "user@example.invalid".into(),
        password_hash: SECRET.into(),
        roles: vec!["Editor".into()],
        scopes: vec![],
        disabled: false,
    };
    let rendered = format!("{user:?}");
    assert!(rendered.contains("user-1") && rendered.contains("Editor"));
    assert_redacted(rendered);

    let refresh = StoredRefreshToken {
        id: Uuid::new_v4(),
        user_id: "user-1".into(),
        session_id: Uuid::new_v4(),
        session_family_id: Uuid::new_v4(),
        grant_source: RefreshGrantSource::default(),
        authorization_roles: vec![],
        roles: vec![],
        scopes: vec![],
        session: SessionContext::default(),
        refreshable_metadata: None,
        token_hash: SECRET.into(),
        created_at: now(),
        expires_at: now() + Duration::days(1),
        last_used_at: None,
        revoked_at: None,
        replaced_by_token_id: None,
        user_agent: None,
        ip_address: None,
    };
    assert_redacted(format!("{refresh:?}"));

    let challenge = StoredLoginChallenge {
        id: Uuid::new_v4(),
        principal: "user@example.invalid".into(),
        code_hash: SECRET.into(),
        created_at: now(),
        expires_at: now() + Duration::minutes(5),
        attempts: 0,
        max_attempts: 5,
        consumed_at: None,
        channel: Some("email".into()),
    };
    let rendered = format!("{challenge:?}");
    assert!(rendered.contains("email"));
    assert_redacted(rendered);
}

#[test]
fn issued_one_time_values_redact_plaintext_in_debug() {
    let issued = IssuedLoginChallenge {
        challenge_id: Uuid::new_v4(),
        principal: "user@example.invalid".into(),
        code: SECRET.into(),
        expires_at: now(),
        max_attempts: 5,
        channel: None,
    };
    assert_redacted(format!("{issued:?}"));

    let directive = GraphqlRefreshCookieDirective::Set {
        refresh_token: SECRET.into(),
        refresh_token_expires_at: "2030-01-01T00:00:00Z".into(),
    };
    let rendered = format!("{directive:?}");
    assert!(rendered.contains("2030-01-01T00:00:00Z"));
    assert_redacted(rendered);
    assert_eq!(
        format!("{:?}", GraphqlRefreshCookieDirective::Clear),
        "Clear"
    );
}

#[test]
fn already_redacted_secret_carriers_stay_redacted() {
    let user = AuthUser {
        user_id: "user-1".into(),
        session_id: Uuid::new_v4(),
        roles: vec![],
        scopes: vec![],
        session: SessionContext::default(),
        token_claims: AccessTokenMetadata::default(),
    };
    assert_redacted(format!(
        "{:?}",
        AuthPayload {
            user: user.clone(),
            access_token: SECRET.into(),
            access_token_expires_at: now(),
            refresh_token: SECRET.into(),
            refresh_token_expires_at: now(),
        }
    ));
    assert_redacted(format!(
        "{:?}",
        AccessTokenOnlyGrant {
            access_token: SECRET.into(),
            access_token_expires_at: now(),
            user,
        }
    ));
    assert_redacted(format!(
        "{:?}",
        PasswordResetToken {
            user_id: "user-1".into(),
            token_id: Uuid::new_v4(),
            token: SECRET.into(),
            expires_at: now(),
        }
    ));
    assert_redacted(format!(
        "{:?}",
        IssuedApiToken {
            token_id: Uuid::new_v4(),
            token: SECRET.into(),
            display_name: "display".into(),
            subject: "svc".into(),
            principal_kind: ApiTokenPrincipalKind::service(),
            scopes: vec![],
            audience: None,
            resource_type: None,
            resource_id: None,
            created_at: now(),
            expires_at: now(),
        }
    ));
    assert_redacted(format!(
        "{:?}",
        IssuedPurposeToken {
            token: SECRET.into(),
            subject: "user-1".into(),
            purpose: "purpose".into(),
            audience: "aud".into(),
            session_id: None,
            scopes: vec![],
            claims: Default::default(),
            expires_at: now(),
        }
    ));
    assert_redacted(format!(
        "{:?}",
        TotpSecret {
            raw_secret: SECRET.as_bytes().to_vec(),
            base32_secret: SECRET.into(),
        }
    ));
    assert_redacted(format!(
        "{:?}",
        TotpProvisioning {
            issuer: "issuer".into(),
            account_name: "user@example.invalid".into(),
            secret: SECRET.into(),
            uri: format!("otpauth://totp/x?secret={SECRET}"),
        }
    ));
}
