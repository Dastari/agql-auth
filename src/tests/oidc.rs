use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use percent_encoding::percent_decode_str;
use serde_json::{Value as JsonValue, json};
use time::{Duration, OffsetDateTime};

use super::{MemoryRefreshTokenStore, MemoryUserStore, metadata, test_auth_service};
use crate::prelude::*;

type RecordedPost = (String, Vec<(String, String)>);

const TENANT_ID: &str = "11111111-1111-1111-1111-111111111111";
const OBJECT_ID: &str = "22222222-2222-2222-2222-222222222222";
const SUBJECT: &str = "subject-value";
const CLIENT_ID: &str = "client-id";
const REDIRECT_URI: &str = "https://app.example.test/auth/microsoft/callback";
const DISCOVERY_URL: &str = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0/.well-known/openid-configuration";
const AUTH_ENDPOINT: &str =
    "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/oauth2/v2.0/authorize";
const TOKEN_ENDPOINT: &str =
    "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token";
const JWKS_URI: &str =
    "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/discovery/v2.0/keys";
const ISSUER: &str = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0";

const RSA_PRIVATE_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTL
UTv4l4sggh5/CYYi/cvI+SXVT9kPWSKXxJXBXd/4LkvcPuUakBoAkfh+eiFVMh2V
rUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8H
oGfG/AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBI
Mc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi+yUod+j8MtvIj812dkS4QMiRVN/
by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQIDAQABAoIBAHREk0I0O9DvECKd
WUpAmF3mY7oY9PNQiu44Yaf+AoSuyRpRUGTMIgc3u3eivOE8ALX0BmYUO5JtuRNZ
Dpvt4SAwqCnVUinIf6C+eH/wSurCpapSM0BAHp4aOA7igptyOMgMPYBHNA1e9A7j
E0dCxKWMl3DSWNyjQTk4zeRGEAEfbNjHrq6YCtjHSZSLmWiG80hnfnYos9hOr5Jn
LnyS7ZmFE/5P3XVrxLc/tQ5zum0R4cbrgzHiQP5RgfxGJaEi7XcgherCCOgurJSS
bYH29Gz8u5fFbS+Yg8s+OiCss3cs1rSgJ9/eHZuzGEdUZVARH6hVMjSuwvqVTFaE
8AgtleECgYEA+uLMn4kNqHlJS2A5uAnCkj90ZxEtNm3E8hAxUrhssktY5XSOAPBl
xyf5RuRGIImGtUVIr4HuJSa5TX48n3Vdt9MYCprO/iYl6moNRSPt5qowIIOJmIjY
2mqPDfDt/zw+fcDD3lmCJrFlzcnh0uea1CohxEbQnL3cypeLt+WbU6kCgYEAzSp1
9m1ajieFkqgoB0YTpt/OroDx38vvI5unInJlEeOjQ+oIAQdN2wpxBvTrRorMU6P0
7mFUbt1j+Co6CbNiw+X8HcCaqYLR5clbJOOWNR36PuzOpQLkfK8woupBxzW9B8gZ
mY8rB1mbJ+/WTPrEJy6YGmIEBkWylQ2VpW8O4O0CgYEApdbvvfFBlwD9YxbrcGz7
MeNCFbMz+MucqQntIKoKJ91ImPxvtc0y6e/Rhnv0oyNlaUOwJVu0yNgNG117w0g4
t/+Q38mvVC5xV7/cn7x9UMFk6MkqVir3dYGEqIl/OP1grY2Tq9HtB5iyG9L8NIam
QOLMyUqqMUILxdthHyFmiGkCgYEAn9+PjpjGMPHxL0gj8Q8VbzsFtou6b1deIRRA
2CHmSltltR1gYVTMwXxQeUhPMmgkMqUXzs4/WijgpthY44hK1TaZEKIuoxrS70nJ
4WQLf5a9k1065fDsFZD6yGjdGxvwEmlGMZgTwqV7t1I4X0Ilqhav5hcs5apYL7gn
PYPeRz0CgYALHCj/Ji8XSsDoF/MhVhnGdIs2P99NNdmo3R2Pv0CuZbDKMU559LJH
UvrKS8WkuWRDuKrz1W/EQKApFjDGpdqToZqriUFQzwy7mR3ayIiogzNtHcvbDHx8
oFnGY0OFksX/ye0/XGpy2SFxYRwGU98HPYeBvAQQrVjdkzfy7BmXQQ==
-----END RSA PRIVATE KEY-----"#;

#[derive(Clone)]
struct MockOidcHttpClient {
    get_responses: Arc<Mutex<HashMap<String, JsonValue>>>,
    gets: Arc<Mutex<Vec<String>>>,
    post_response: Arc<Mutex<JsonValue>>,
    posts: Arc<Mutex<Vec<RecordedPost>>>,
}

impl MockOidcHttpClient {
    fn new() -> Self {
        let mut get_responses = HashMap::new();
        get_responses.insert(DISCOVERY_URL.to_string(), discovery_document());
        get_responses.insert(JWKS_URI.to_string(), jwks_document("rsa01"));

        Self {
            get_responses: Arc::new(Mutex::new(get_responses)),
            gets: Arc::new(Mutex::new(Vec::new())),
            post_response: Arc::new(Mutex::new(json!({}))),
            posts: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn set_token_response(&self, token: String) {
        *self.post_response.lock().unwrap() = json!({
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "openid profile email",
            "access_token": "opaque-provider-access-token",
            "id_token": token
        });
    }

    fn get_count(&self, url: &str) -> usize {
        self.gets
            .lock()
            .unwrap()
            .iter()
            .filter(|seen| seen.as_str() == url)
            .count()
    }
}

#[async_trait]
impl OidcHttpClient for MockOidcHttpClient {
    async fn get_json(&self, url: &str) -> crate::AuthResult<JsonValue> {
        self.gets.lock().unwrap().push(url.to_string());
        self.get_responses
            .lock()
            .unwrap()
            .get(url)
            .cloned()
            .ok_or_else(|| AuthError::OidcDiscovery(format!("missing mock GET {url}")))
    }

    async fn post_form_json(
        &self,
        url: &str,
        form: &[(String, String)],
    ) -> crate::AuthResult<JsonValue> {
        self.posts
            .lock()
            .unwrap()
            .push((url.to_string(), form.to_vec()));
        Ok(self.post_response.lock().unwrap().clone())
    }
}

#[derive(Clone, Default)]
struct MemoryOAuthStateStore {
    states: Arc<Mutex<HashMap<(String, String), OAuthLoginState>>>,
}

#[async_trait]
impl OAuthStateStore for MemoryOAuthStateStore {
    async fn insert_oauth_state(&self, state: OAuthLoginState) -> crate::AuthResult<()> {
        self.states.lock().unwrap().insert(
            (state.provider_name.clone(), state.state_hash.clone()),
            state,
        );
        Ok(())
    }

    async fn consume_oauth_state(
        &self,
        provider_name: &str,
        state_hash: &str,
        consumed_at: OffsetDateTime,
    ) -> crate::AuthResult<Option<OAuthLoginState>> {
        let mut states = self.states.lock().unwrap();
        let Some(state) = states.get_mut(&(provider_name.to_string(), state_hash.to_string()))
        else {
            return Ok(None);
        };

        if state.consumed_at.is_some() {
            return Ok(None);
        }

        let original = state.clone();
        state.consumed_at = Some(consumed_at);
        Ok(Some(original))
    }

    async fn expire_oauth_states(
        &self,
        older_than: OffsetDateTime,
        expired_at: OffsetDateTime,
    ) -> crate::AuthResult<u64> {
        let mut expired = 0;
        for state in self.states.lock().unwrap().values_mut() {
            if state.expires_at <= older_than && state.consumed_at.is_none() {
                state.consumed_at = Some(expired_at);
                expired += 1;
            }
        }
        Ok(expired)
    }
}

#[derive(Clone, Default)]
struct MemoryExternalIdentityStore {
    identities: Arc<Mutex<HashMap<(String, String), ExternalIdentity>>>,
}

#[async_trait]
impl ExternalIdentityStore for MemoryExternalIdentityStore {
    async fn find_external_identity(
        &self,
        provider_name: &str,
        external_subject: &str,
    ) -> crate::AuthResult<Option<ExternalIdentity>> {
        Ok(self
            .identities
            .lock()
            .unwrap()
            .get(&(provider_name.to_string(), external_subject.to_string()))
            .cloned())
    }

    async fn link_external_identity(&self, identity: ExternalIdentity) -> crate::AuthResult<()> {
        self.identities.lock().unwrap().insert(
            (
                identity.provider_name.clone(),
                identity.external_subject.clone(),
            ),
            identity,
        );
        Ok(())
    }

    async fn update_external_identity_claims_snapshot(
        &self,
        provider_name: &str,
        external_subject: &str,
        claims_snapshot: JsonValue,
        updated_at: OffsetDateTime,
    ) -> crate::AuthResult<()> {
        if let Some(identity) = self
            .identities
            .lock()
            .unwrap()
            .get_mut(&(provider_name.to_string(), external_subject.to_string()))
        {
            identity.claims_snapshot = claims_snapshot;
            identity.updated_at = updated_at;
        }
        Ok(())
    }
}

struct StaticProvisioner {
    user_id: String,
}

struct AcceptingAssuranceMapper;

#[async_trait]
impl ClaimsMapper for AcceptingAssuranceMapper {
    async fn map_claims(&self, claims: &ValidatedOidcClaims) -> crate::AuthResult<MappedClaims> {
        let assurance = SessionAssurance::new(
            claims.auth_time.expect("test auth_time"),
            claims.amr.clone().expect("test amr"),
            claims.acr.clone(),
            Some(claims.provider_name.clone()),
            MfaAcceptance::Satisfied,
        )
        .unwrap();
        Ok(MappedClaims {
            roles: vec![],
            scopes: vec![],
            assurance: Some(assurance),
        })
    }
}

#[async_trait]
impl ExternalUserProvisioner for StaticProvisioner {
    async fn resolve_external_user(
        &self,
        _claims: &ValidatedOidcClaims,
        existing_identity: Option<&ExternalIdentity>,
        mapped_claims: &MappedClaims,
    ) -> crate::AuthResult<ProvisionedExternalUser> {
        let user_id = existing_identity
            .map(|identity| identity.user_id.clone())
            .unwrap_or_else(|| self.user_id.clone());
        Ok(ProvisionedExternalUser::from_mapped_claims(
            user_id,
            mapped_claims,
        ))
    }
}

#[test]
fn pkce_generation_uses_s256() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    assert_eq!(
        pkce_s256_challenge(verifier),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );

    let pair = generate_pkce_pair();
    assert!((43..=128).contains(&pair.code_verifier.len()));
    assert_eq!(
        pair.code_challenge,
        pkce_s256_challenge(&pair.code_verifier)
    );
    assert_ne!(pair.code_verifier, pair.code_challenge);
}

#[tokio::test]
async fn state_nonce_and_authorization_url_are_generated_and_consumed_once() {
    let (provider, client) = provider_and_client();
    let state_store = MemoryOAuthStateStore::default();
    let request = provider
        .create_authorization_request(&state_store)
        .await
        .unwrap();

    assert!(request.authorization_url.starts_with(AUTH_ENDPOINT));
    assert!(request.authorization_url.contains("client_id=client-id"));
    assert!(
        request
            .authorization_url
            .contains("redirect_uri=https%3A%2F%2Fapp.example.test%2Fauth%2Fmicrosoft%2Fcallback")
    );
    assert!(request.authorization_url.contains("response_type=code"));
    assert!(request.authorization_url.contains("response_mode=query"));
    assert!(
        request
            .authorization_url
            .contains("scope=openid%20profile%20email")
    );
    assert!(
        request
            .authorization_url
            .contains("code_challenge_method=S256")
    );
    assert!(!request.state.is_empty());
    assert!(!request.nonce.is_empty());

    let token = signed_id_token(valid_claims(&request.nonce), "rsa01");
    client.set_token_response(token);
    provider
        .handle_callback(
            &state_store,
            OidcCallbackInput::code_and_state("auth-code", request.state.clone()),
        )
        .await
        .unwrap();

    let replay = provider
        .handle_callback(
            &state_store,
            OidcCallbackInput::code_and_state("auth-code", request.state),
        )
        .await
        .unwrap_err();
    assert!(matches!(replay, AuthError::InvalidOAuthState));
}

#[tokio::test]
async fn oauth_state_store_contract_returns_pre_consumption_snapshot() {
    let store = MemoryOAuthStateStore::default();
    let state = OAuthLoginState {
        provider_name: "microsoft".to_string(),
        state_hash: hash_oauth_state("state-value"),
        nonce: "nonce".to_string(),
        code_verifier: "code-verifier".to_string(),
        redirect_uri: REDIRECT_URI.to_string(),
        scopes: vec!["openid".to_string()],
        authorization_policy: None,
        created_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + Duration::minutes(10),
        consumed_at: None,
    };
    store.insert_oauth_state(state.clone()).await.unwrap();

    let consumed = store
        .consume_oauth_state(
            &state.provider_name,
            &state.state_hash,
            OffsetDateTime::now_utc(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(consumed.consumed_at.is_none());
    assert!(
        store
            .states
            .lock()
            .unwrap()
            .get(&(state.provider_name.clone(), state.state_hash.clone()))
            .unwrap()
            .consumed_at
            .is_some()
    );

    let replay = store
        .consume_oauth_state(
            &state.provider_name,
            &state.state_hash,
            OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
    assert!(replay.is_none());
}

#[test]
fn stable_identity_key_prefers_microsoft_tid_and_oid() {
    assert_eq!(
        stable_external_subject(
            &OidcProviderKind::MicrosoftEntra,
            ISSUER,
            SUBJECT,
            Some(TENANT_ID),
            Some(OBJECT_ID)
        ),
        format!("{TENANT_ID}:{OBJECT_ID}")
    );

    assert_eq!(
        stable_external_subject(
            &OidcProviderKind::MicrosoftEntra,
            ISSUER,
            SUBJECT,
            Some(TENANT_ID),
            None
        ),
        format!("{ISSUER}:{SUBJECT}")
    );

    assert_eq!(
        stable_external_subject(&OidcProviderKind::Generic, ISSUER, SUBJECT, None, None),
        format!("{ISSUER}:{SUBJECT}")
    );
}

#[tokio::test]
async fn microsoft_claim_mapper_maps_roles_groups_tenant_and_object_id() {
    let mapper = MicrosoftClaimsMapper::new()
        .map_role_to_role("App.Admin", "Admin")
        .map_role_to_scope("App.Admin", "admin.write")
        .map_group_to_role("group-1", "GroupMember")
        .map_group_to_scope("group-1", "group.read")
        .map_tenant_to_scope(TENANT_ID, "tenant.read")
        .map_object_id_to_role(OBJECT_ID, "NamedOperator")
        .map_object_id_to_scope(OBJECT_ID, "admin.write");

    let claims = ValidatedOidcClaims {
        provider_name: "microsoft".to_string(),
        issuer: ISSUER.to_string(),
        audiences: vec![CLIENT_ID.to_string()],
        subject: SUBJECT.to_string(),
        external_subject: format!("{TENANT_ID}:{OBJECT_ID}"),
        expires_at: OffsetDateTime::now_utc() + Duration::minutes(5),
        not_before: Some(OffsetDateTime::now_utc() - Duration::minutes(1)),
        issued_at: OffsetDateTime::now_utc(),
        auth_time: None,
        amr: None,
        acr: None,
        acrs: None,
        nonce: "nonce".to_string(),
        tenant_id: Some(TENANT_ID.to_string()),
        object_id: Some(OBJECT_ID.to_string()),
        email: None,
        name: None,
        preferred_username: None,
        roles: vec!["App.Admin".to_string()],
        groups: vec!["group-1".to_string()],
        raw: json!({}),
    };

    let mapped = mapper.map_claims(&claims).await.unwrap();
    assert_eq!(
        mapped.roles,
        vec![
            "Admin".to_string(),
            "GroupMember".to_string(),
            "NamedOperator".to_string()
        ]
    );
    assert_eq!(
        mapped.scopes,
        vec![
            "admin.write".to_string(),
            "group.read".to_string(),
            "tenant.read".to_string()
        ]
    );
}

#[tokio::test]
async fn mocked_callback_validates_id_token_and_issues_local_session() {
    let (provider, client) = provider_and_client();
    let state_store = MemoryOAuthStateStore::default();
    let identity_store = MemoryExternalIdentityStore::default();
    let auth = test_auth_service(
        MemoryUserStore::default(),
        MemoryRefreshTokenStore::default(),
    );
    let request = provider
        .create_authorization_request(&state_store)
        .await
        .unwrap();
    let mut provider_claims = valid_claims(&request.nonce);
    provider_claims["auth_time"] = json!(OffsetDateTime::now_utc().unix_timestamp());
    provider_claims["amr"] = json!(["pwd", "otp"]);
    provider_claims["acr"] = json!("urn:example:loa:2");
    client.set_token_response(signed_id_token(provider_claims, "rsa01"));

    let mapper = MicrosoftClaimsMapper::new()
        .map_role_to_role("App.Admin", "Admin")
        .map_group_to_scope("group-1", "group.read");
    let result = provider
        .login_with_callback(
            &auth,
            &state_store,
            &identity_store,
            &StaticProvisioner {
                user_id: "local-user".to_string(),
            },
            &mapper,
            OidcCallbackInput::code_and_state("auth-code", request.state),
            metadata(),
        )
        .await
        .unwrap();

    assert_eq!(result.auth.user.user_id, "local-user");
    assert_eq!(
        result.auth.user.session.auth_method,
        AuthMethod::MicrosoftOidc
    );
    assert_eq!(result.auth.user.roles, vec!["Admin".to_string()]);
    assert_eq!(result.auth.user.scopes, vec!["group.read".to_string()]);
    assert!(result.claims.auth_time.is_some());
    assert_eq!(
        result.claims.amr,
        Some(vec!["pwd".to_string(), "otp".to_string()])
    );
    assert_eq!(result.claims.acr.as_deref(), Some("urn:example:loa:2"));
    assert!(result.auth.user.session.assurance.is_none());
    assert!(!result.auth.user.session.mfa.satisfied);
    assert_eq!(
        result.external_identity.external_subject,
        format!("{TENANT_ID}:{OBJECT_ID}")
    );
    assert_eq!(
        auth.authenticate_access_token(&result.auth.access_token)
            .unwrap()
            .session
            .auth_method,
        AuthMethod::MicrosoftOidc
    );
}

#[tokio::test]
async fn oidc_assurance_requires_explicit_host_mapping_before_mfa_is_satisfied() {
    let (provider, client) = provider_and_client();
    let state_store = MemoryOAuthStateStore::default();
    let request = provider
        .create_authorization_request(&state_store)
        .await
        .unwrap();
    let auth_time = OffsetDateTime::now_utc().unix_timestamp();
    let mut claims = valid_claims(&request.nonce);
    claims["auth_time"] = json!(auth_time);
    claims["amr"] = json!([" OTP ", "pwd", "otp"]);
    claims["acr"] = json!("urn:example:loa:2");
    client.set_token_response(signed_id_token(claims, "rsa01"));

    let auth = test_auth_service(
        MemoryUserStore::default(),
        MemoryRefreshTokenStore::default(),
    );
    let result = provider
        .login_with_callback(
            &auth,
            &state_store,
            &MemoryExternalIdentityStore::default(),
            &StaticProvisioner {
                user_id: "local-user".to_string(),
            },
            &AcceptingAssuranceMapper,
            OidcCallbackInput::code_and_state("auth-code", request.state),
            metadata(),
        )
        .await
        .unwrap();

    assert!(result.auth.user.session.mfa.satisfied);
    assert_eq!(result.auth.user.token_claims.auth_time, Some(auth_time));
    assert_eq!(
        result.auth.user.token_claims.amr,
        Some(vec!["otp".to_string(), "pwd".to_string()])
    );
}

#[tokio::test]
async fn oidc_assurance_claims_enforce_types_sizes_and_timestamp_bounds() {
    let valid = run_validation_case(|claims, _| {
        claims["auth_time"] = json!(OffsetDateTime::now_utc().unix_timestamp());
        claims["amr"] = json!([" OTP ", "pwd", "otp"]);
        claims["acr"] = json!("urn:example:loa:2");
    })
    .await
    .unwrap();
    assert_eq!(
        valid.claims.amr,
        Some(vec!["otp".to_string(), "pwd".to_string()])
    );

    let wrong_auth_time = run_validation_case(|claims, _| claims["auth_time"] = json!("now")).await;
    assert!(matches!(
        wrong_auth_time,
        Err(AuthError::OidcTokenValidation(_))
    ));
    let wrong_amr = run_validation_case(|claims, _| claims["amr"] = json!("otp")).await;
    assert!(matches!(wrong_amr, Err(AuthError::OidcTokenValidation(_))));
    let wrong_acr = run_validation_case(|claims, _| claims["acr"] = json!(["loa2"])).await;
    assert!(matches!(wrong_acr, Err(AuthError::OidcTokenValidation(_))));
    let negative = run_validation_case(|claims, _| claims["auth_time"] = json!(-1)).await;
    assert!(matches!(negative, Err(AuthError::OidcTokenValidation(_))));
    let invalid_timestamp =
        run_validation_case(|claims, _| claims["auth_time"] = json!(i64::MAX)).await;
    assert!(matches!(
        invalid_timestamp,
        Err(AuthError::OidcTokenValidation(_))
    ));
    let too_many = run_validation_case(|claims, _| {
        claims["amr"] = json!(
            (0..=MAX_ASSURANCE_METHODS)
                .map(|index| format!("m{index}"))
                .collect::<Vec<_>>()
        );
    })
    .await;
    assert!(matches!(too_many, Err(AuthError::OidcTokenValidation(_))));
    let too_many_duplicates = run_validation_case(|claims, _| {
        claims["amr"] = json!(vec!["otp"; MAX_ASSURANCE_METHODS + 1]);
    })
    .await;
    assert!(matches!(
        too_many_duplicates,
        Err(AuthError::OidcTokenValidation(_))
    ));
    let long_method = run_validation_case(|claims, _| {
        claims["amr"] = json!(["x".repeat(MAX_ASSURANCE_METHOD_LENGTH + 1)])
    })
    .await;
    assert!(matches!(
        long_method,
        Err(AuthError::OidcTokenValidation(_))
    ));
    let long_acr = run_validation_case(|claims, _| {
        claims["acr"] = json!("x".repeat(MAX_ASSURANCE_CONTEXT_LENGTH + 1))
    })
    .await;
    assert!(matches!(long_acr, Err(AuthError::OidcTokenValidation(_))));
}

#[tokio::test]
async fn generic_oidc_accepts_id_token_without_nbf() {
    let (provider, client) = generic_provider_and_client();
    let state_store = MemoryOAuthStateStore::default();
    let request = provider
        .create_authorization_request(&state_store)
        .await
        .unwrap();
    let mut claims = valid_claims(&request.nonce);
    claims.as_object_mut().unwrap().remove("nbf");
    client.set_token_response(signed_id_token(claims, "rsa01"));

    let outcome = provider
        .handle_callback(
            &state_store,
            OidcCallbackInput::code_and_state("auth-code", request.state),
        )
        .await
        .unwrap();
    assert!(outcome.claims.not_before.is_none());
}

#[tokio::test]
async fn generic_oidc_rejects_future_nbf_when_present() {
    let err = run_generic_validation_case(|claims, _nonce| {
        claims["nbf"] = json!((OffsetDateTime::now_utc() + Duration::hours(1)).unix_timestamp());
    })
    .await
    .unwrap_err();
    assert!(matches!(err, AuthError::OidcTokenValidation(_)));
}

#[tokio::test]
async fn oidc_rejects_multi_audience_without_azp() {
    let err = run_generic_validation_case(|claims, _nonce| {
        claims["aud"] = json!([CLIENT_ID, "api://extra"]);
    })
    .await
    .unwrap_err();
    assert!(matches!(err, AuthError::OidcTokenValidation(_)));
}

#[tokio::test]
async fn oidc_accepts_multi_audience_with_trusted_extra_audience_and_azp() {
    let client = MockOidcHttpClient::new();
    let mut config = OidcProviderConfig::new("generic", DISCOVERY_URL, CLIENT_ID, REDIRECT_URI);
    config.allowed_additional_audiences = vec!["api://extra".to_string()];
    let provider = OidcProvider::new(config, Arc::new(client.clone())).unwrap();
    let state_store = MemoryOAuthStateStore::default();
    let request = provider
        .create_authorization_request(&state_store)
        .await
        .unwrap();
    let mut claims = valid_claims(&request.nonce);
    claims["aud"] = json!([CLIENT_ID, "api://extra"]);
    claims["azp"] = json!(CLIENT_ID);
    client.set_token_response(signed_id_token(claims, "rsa01"));

    let outcome = provider
        .handle_callback(
            &state_store,
            OidcCallbackInput::code_and_state("auth-code", request.state),
        )
        .await
        .unwrap();
    assert_eq!(
        outcome.claims.audiences,
        vec![CLIENT_ID.to_string(), "api://extra".to_string()]
    );
}

#[tokio::test]
async fn oidc_rejects_untrusted_extra_audience() {
    let err = run_generic_validation_case(|claims, _nonce| {
        claims["aud"] = json!([CLIENT_ID, "api://untrusted"]);
        claims["azp"] = json!(CLIENT_ID);
    })
    .await
    .unwrap_err();
    assert!(matches!(err, AuthError::OidcTokenValidation(_)));
}

#[tokio::test]
async fn callback_rejects_invalid_nonce() {
    let err = run_validation_case(|claims, _nonce| {
        claims["nonce"] = json!("wrong-nonce");
    })
    .await
    .unwrap_err();
    assert!(matches!(err, AuthError::OidcTokenValidation(_)));
}

#[tokio::test]
async fn callback_rejects_invalid_issuer() {
    let err = run_validation_case(|claims, _nonce| {
        claims["iss"] = json!("https://evil.example.test");
    })
    .await
    .unwrap_err();
    assert!(matches!(err, AuthError::OidcTokenValidation(_)));
}

#[tokio::test]
async fn callback_rejects_invalid_audience() {
    let err = run_validation_case(|claims, _nonce| {
        claims["aud"] = json!("other-client");
    })
    .await
    .unwrap_err();
    assert!(matches!(err, AuthError::OidcTokenValidation(_)));
}

#[tokio::test]
async fn callback_rejects_expired_token() {
    let err = run_validation_case(|claims, _nonce| {
        let now = OffsetDateTime::now_utc();
        claims["exp"] = json!((now - Duration::minutes(10)).unix_timestamp());
        claims["nbf"] = json!((now - Duration::minutes(20)).unix_timestamp());
        claims["iat"] = json!((now - Duration::minutes(20)).unix_timestamp());
    })
    .await
    .unwrap_err();
    assert!(matches!(err, AuthError::OidcTokenValidation(_)));
}

#[tokio::test]
async fn callback_rejects_unknown_key_id() {
    let (provider, client) = provider_and_client();
    let state_store = MemoryOAuthStateStore::default();
    let request = provider
        .create_authorization_request(&state_store)
        .await
        .unwrap();
    client.set_token_response(signed_id_token(valid_claims(&request.nonce), "missing"));

    let err = provider
        .handle_callback(
            &state_store,
            OidcCallbackInput::code_and_state("auth-code", request.state),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::OidcTokenValidation(_)));
}

#[tokio::test]
async fn unknown_kid_uses_forced_refresh_cooldown() {
    let (provider, client) = provider_and_client();
    let state_store = MemoryOAuthStateStore::default();

    for _ in 0..2 {
        let request = provider
            .create_authorization_request(&state_store)
            .await
            .unwrap();
        client.set_token_response(signed_id_token(valid_claims(&request.nonce), "missing"));
        let err = provider
            .handle_callback(
                &state_store,
                OidcCallbackInput::code_and_state("auth-code", request.state),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::OidcTokenValidation(_)));
    }

    assert_eq!(client.get_count(JWKS_URI), 2);
}

#[tokio::test]
async fn discovery_cache_respects_ttl() {
    let client = MockOidcHttpClient::new();
    let mut config = MicrosoftEntraConfig::single_tenant(TENANT_ID, CLIENT_ID, REDIRECT_URI)
        .into_oidc_provider_config()
        .unwrap();
    config.discovery_cache_ttl = Duration::milliseconds(1);
    let provider = OidcProvider::new(config, Arc::new(client.clone())).unwrap();

    provider.discover().await.unwrap();
    provider.discover().await.unwrap();
    assert_eq!(client.get_count(DISCOVERY_URL), 1);

    std::thread::sleep(std::time::Duration::from_millis(2));
    provider.discover().await.unwrap();
    assert_eq!(client.get_count(DISCOVERY_URL), 2);
}

#[tokio::test]
async fn callback_rejects_disallowed_tenant() {
    let err = run_validation_case(|claims, _nonce| {
        claims["tid"] = json!("33333333-3333-3333-3333-333333333333");
        claims["iss"] =
            json!("https://login.microsoftonline.com/33333333-3333-3333-3333-333333333333/v2.0");
    })
    .await
    .unwrap_err();
    assert!(matches!(err, AuthError::OidcTokenValidation(_)));
}

#[tokio::test]
async fn callback_rejects_microsoft_consumers_unless_enabled() {
    let mut config = OidcProviderConfig::new("microsoft", DISCOVERY_URL, CLIENT_ID, REDIRECT_URI);
    config.provider_kind = OidcProviderKind::MicrosoftEntra;
    config.allowed_issuers = vec!["https://login.microsoftonline.com/{tenantid}/v2.0".to_string()];
    config.allowed_tenants = Vec::new();
    config.allow_consumer_accounts = false;

    let client = MockOidcHttpClient::new();
    let provider = OidcProvider::new(config, Arc::new(client.clone())).unwrap();
    let state_store = MemoryOAuthStateStore::default();
    let request = provider
        .create_authorization_request(&state_store)
        .await
        .unwrap();
    let mut claims = valid_claims(&request.nonce);
    claims["tid"] = json!("9188040d-6c67-4c5b-b112-36a304b66dad");
    claims["oid"] = json!("consumer-object-id");
    claims["iss"] =
        json!("https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0");
    client.set_token_response(signed_id_token(claims, "rsa01"));

    let err = provider
        .handle_callback(
            &state_store,
            OidcCallbackInput::code_and_state("auth-code", request.state),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::OidcTokenValidation(_)));
}

#[tokio::test]
async fn callback_rejects_invalid_signature() {
    let (provider, client) = provider_and_client();
    let state_store = MemoryOAuthStateStore::default();
    let request = provider
        .create_authorization_request(&state_store)
        .await
        .unwrap();
    let mut token = signed_id_token(valid_claims(&request.nonce), "rsa01");
    token.push('x');
    client.set_token_response(token);

    let err = provider
        .handle_callback(
            &state_store,
            OidcCallbackInput::code_and_state("auth-code", request.state),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::OidcTokenValidation(_)));
}

#[tokio::test]
async fn callback_rejects_replayed_state() {
    let (provider, client) = provider_and_client();
    let state_store = MemoryOAuthStateStore::default();
    let request = provider
        .create_authorization_request(&state_store)
        .await
        .unwrap();
    client.set_token_response(signed_id_token(valid_claims(&request.nonce), "rsa01"));

    provider
        .handle_callback(
            &state_store,
            OidcCallbackInput::code_and_state("auth-code", request.state.clone()),
        )
        .await
        .unwrap();

    let err = provider
        .handle_callback(
            &state_store,
            OidcCallbackInput::code_and_state("auth-code", request.state),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidOAuthState));
}

#[test]
fn oidc_token_response_debug_redacts_provider_tokens_and_raw_response() {
    let response = OidcTokenResponse {
        access_token: Some("provider-access-token".to_string()),
        refresh_token: Some("provider-refresh-token".to_string()),
        id_token: "provider-id-token".to_string(),
        token_type: Some("Bearer".to_string()),
        expires_in: Some(3600),
        scope: Some("openid profile".to_string()),
        raw: json!({
            "access_token": "provider-access-token",
            "refresh_token": "provider-refresh-token",
            "id_token": "provider-id-token"
        }),
    };

    let debug = format!("{response:?}");
    assert!(!debug.contains("provider-access-token"));
    assert!(!debug.contains("provider-refresh-token"));
    assert!(!debug.contains("provider-id-token"));
    assert!(debug.contains("Bearer"));
    assert!(debug.contains("openid profile"));
}

#[tokio::test]
async fn typed_authorization_options_are_encoded_once_and_bound_to_state() {
    let (provider, _client) = provider_and_client();
    let store = MemoryOAuthStateStore::default();
    let options = OidcAuthorizationOptions {
        prompt: vec![OidcPrompt::Login, OidcPrompt::Consent],
        max_age: Some(0),
        acr_values: Vec::new(),
        id_token_claims: vec![
            OidcIdTokenClaimRequest::EssentialAuthTime,
            OidcIdTokenClaimRequest::EssentialAcr {
                values: vec!["urn:example:loa:2&next=evil".to_string()],
            },
        ],
    };
    let expected = options.validate().unwrap();
    let request = provider
        .create_authorization_request_with_options(&store, options)
        .await
        .unwrap();
    let pairs = query_pairs(&request.authorization_url);

    assert_eq!(query_values(&pairs, "prompt"), vec!["login consent"]);
    assert_eq!(query_values(&pairs, "max_age"), vec!["0"]);
    assert!(query_values(&pairs, "acr_values").is_empty());
    let claims = query_values(&pairs, "claims");
    assert_eq!(claims.len(), 1);
    let claims_json: JsonValue = serde_json::from_str(claims[0]).unwrap();
    assert_eq!(claims_json["id_token"]["auth_time"]["essential"], true);
    assert_eq!(
        claims_json["id_token"]["acr"]["values"][0],
        "urn:example:loa:2&next=evil"
    );
    assert!(query_values(&pairs, "next").is_empty());
    assert_eq!(request.authorization_policy.as_ref(), Some(&expected));

    let stored = store
        .states
        .lock()
        .unwrap()
        .values()
        .next()
        .unwrap()
        .clone();
    assert_eq!(stored.authorization_policy.as_ref(), Some(&expected));
    let debug = format!("{request:?} {stored:?}");
    assert!(!debug.contains(&request.state));
    assert!(!debug.contains(&request.nonce));
    assert!(!debug.contains(&request.code_verifier));
    assert!(!debug.contains(&request.authorization_url));
    assert!(!debug.contains("urn:example:loa:2&next=evil"));
}

#[tokio::test]
async fn default_authorization_request_keeps_standard_semantics_and_no_bound_policy() {
    let (provider, client) = provider_and_client();
    let store = MemoryOAuthStateStore::default();
    let request = provider.create_authorization_request(&store).await.unwrap();
    let pairs = query_pairs(&request.authorization_url);

    for name in [
        "client_id",
        "redirect_uri",
        "response_type",
        "response_mode",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
    ] {
        assert_eq!(
            query_values(&pairs, name).len(),
            1,
            "unexpected {name} count"
        );
    }
    for name in ["prompt", "max_age", "acr_values", "claims"] {
        assert!(query_values(&pairs, name).is_empty());
    }
    assert!(request.authorization_policy.is_none());

    client.set_token_response(signed_id_token(valid_claims(&request.nonce), "rsa01"));
    let outcome = provider
        .handle_callback(
            &store,
            OidcCallbackInput::code_and_state("auth-code", request.state),
        )
        .await
        .unwrap();
    assert!(!outcome.authorization.is_bound_authorization());
    let expected = OidcAuthorizationOptions {
        max_age: Some(0),
        ..Default::default()
    }
    .validate()
    .unwrap();
    assert!(
        outcome
            .authorization
            .require_bound_policy(&expected)
            .is_err()
    );
}

#[tokio::test]
async fn invalid_options_are_rejected_before_state_is_inserted() {
    let (provider, _client) = provider_and_client();
    let cases = vec![
        OidcAuthorizationOptions {
            prompt: vec![OidcPrompt::None, OidcPrompt::Login],
            ..Default::default()
        },
        OidcAuthorizationOptions {
            prompt: vec![OidcPrompt::Login, OidcPrompt::Login],
            ..Default::default()
        },
        OidcAuthorizationOptions {
            max_age: Some(-1),
            ..Default::default()
        },
        OidcAuthorizationOptions {
            max_age: Some((MAX_OIDC_MAX_AGE_SECONDS + 1) as i64),
            ..Default::default()
        },
        OidcAuthorizationOptions {
            acr_values: vec!["".to_string()],
            ..Default::default()
        },
        OidcAuthorizationOptions {
            acr_values: vec!["loa2".to_string(), "loa2".to_string()],
            ..Default::default()
        },
        OidcAuthorizationOptions {
            acr_values: vec!["loa2\nnext=evil".to_string()],
            ..Default::default()
        },
        OidcAuthorizationOptions {
            id_token_claims: vec![
                OidcIdTokenClaimRequest::EssentialAuthTime,
                OidcIdTokenClaimRequest::EssentialAuthTime,
            ],
            ..Default::default()
        },
        OidcAuthorizationOptions {
            acr_values: vec!["loa2".to_string()],
            id_token_claims: vec![OidcIdTokenClaimRequest::EssentialAcr {
                values: vec!["loa2".to_string()],
            }],
            ..Default::default()
        },
        OidcAuthorizationOptions {
            acr_values: vec!["x".repeat(MAX_OIDC_AUTHORIZATION_VALUE_LENGTH + 1)],
            ..Default::default()
        },
    ];

    for options in cases {
        let store = MemoryOAuthStateStore::default();
        let error = provider
            .create_authorization_request_with_options(&store, options)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            AuthError::InvalidOidcAuthorizationOptions(_)
        ));
        assert!(store.states.lock().unwrap().is_empty());
    }

    let malformed = serde_json::from_str::<OidcAuthorizationOptions>(r#"{"max_age":"0"}"#);
    assert!(malformed.is_err());
    let overflowing =
        serde_json::from_str::<OidcAuthorizationOptions>(r#"{"max_age":18446744073709551615}"#);
    assert!(overflowing.is_err());
}

#[tokio::test]
async fn reserved_endpoint_parameter_collision_is_rejected_before_state_insert() {
    let client = MockOidcHttpClient::new();
    let mut discovery = discovery_document();
    discovery["authorization_endpoint"] = json!(format!("{AUTH_ENDPOINT}?st%61te=attacker"));
    client
        .get_responses
        .lock()
        .unwrap()
        .insert(DISCOVERY_URL.to_string(), discovery);
    let provider = OidcProvider::new(
        MicrosoftEntraConfig::single_tenant(TENANT_ID, CLIENT_ID, REDIRECT_URI)
            .into_oidc_provider_config()
            .unwrap(),
        Arc::new(client),
    )
    .unwrap();
    let store = MemoryOAuthStateStore::default();
    let error = provider
        .create_authorization_request_with_options(
            &store,
            OidcAuthorizationOptions {
                max_age: Some(0),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        AuthError::InvalidOidcAuthorizationOptions(_)
    ));
    assert!(store.states.lock().unwrap().is_empty());
}

#[test]
fn legacy_oauth_state_deserializes_without_authorization_policy() {
    let value = json!({
        "provider_name": "generic",
        "state_hash": "stored-hash",
        "nonce": "stored-nonce",
        "code_verifier": "stored-verifier",
        "redirect_uri": REDIRECT_URI,
        "scopes": ["openid"],
        "created_at": OffsetDateTime::now_utc(),
        "expires_at": OffsetDateTime::now_utc() + Duration::minutes(5),
        "consumed_at": null
    });
    let state: OAuthLoginState = serde_json::from_value(value).unwrap();
    assert!(state.authorization_policy.is_none());
    let debug = format!("{state:?}");
    assert!(!debug.contains("stored-hash"));
    assert!(!debug.contains("stored-nonce"));
    assert!(!debug.contains("stored-verifier"));
}

#[tokio::test]
async fn unknown_stored_policy_version_fails_closed_before_token_exchange() {
    let (provider, client) = provider_and_client();
    let store = MemoryOAuthStateStore::default();
    let request = provider
        .create_authorization_request_with_options(
            &store,
            OidcAuthorizationOptions {
                max_age: Some(0),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let key = ("microsoft".to_string(), hash_oauth_state(&request.state));
    {
        let mut states = store.states.lock().unwrap();
        let state = states.get_mut(&key).unwrap();
        let mut policy =
            serde_json::to_value(state.authorization_policy.as_ref().unwrap()).unwrap();
        policy["version"] = json!(99);
        state.authorization_policy = Some(serde_json::from_value(policy).unwrap());
    }

    let error = provider
        .handle_callback(
            &store,
            OidcCallbackInput::code_and_state("secret-code", request.state),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, AuthError::OidcTokenValidation(_)));
    assert!(client.posts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn bound_max_age_and_skew_boundaries_are_enforced_with_injected_clock() {
    let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
    let options = OidcAuthorizationOptions {
        max_age: Some(60),
        ..Default::default()
    };

    let exact = run_bound_case(now, options.clone(), |claims| {
        claims["auth_time"] = json!((now - Duration::seconds(65)).unix_timestamp());
    })
    .await
    .unwrap();
    assert_eq!(
        exact.authorization.enforced_auth_time,
        Some(now - Duration::seconds(65))
    );
    exact
        .authorization
        .require_bound_policy(&options.validate().unwrap())
        .unwrap();

    let stale = run_bound_case(now, options.clone(), |claims| {
        claims["auth_time"] = json!((now - Duration::seconds(66)).unix_timestamp());
    })
    .await;
    assert!(matches!(stale, Err(AuthError::OidcTokenValidation(_))));

    let future_boundary = run_bound_case(now, options.clone(), |claims| {
        claims["auth_time"] = json!((now + Duration::seconds(5)).unix_timestamp());
    })
    .await;
    assert!(future_boundary.is_ok());
    let future = run_bound_case(now, options.clone(), |claims| {
        claims["auth_time"] = json!((now + Duration::seconds(6)).unix_timestamp());
    })
    .await;
    assert!(matches!(future, Err(AuthError::OidcTokenValidation(_))));

    for auth_time in [
        None,
        Some(json!("now")),
        Some(json!(-1)),
        Some(json!(i64::MAX)),
    ] {
        let result = run_bound_case(now, options.clone(), move |claims| {
            if let Some(value) = auth_time {
                claims["auth_time"] = value;
            }
        })
        .await;
        assert!(matches!(result, Err(AuthError::OidcTokenValidation(_))));
    }

    let zero = OidcAuthorizationOptions {
        max_age: Some(0),
        ..Default::default()
    };
    assert!(
        run_bound_case(now, zero, |claims| {
            claims["auth_time"] = json!(now.unix_timestamp());
        })
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn essential_auth_time_and_exact_standard_acr_fail_closed() {
    let now = OffsetDateTime::now_utc();
    let options = OidcAuthorizationOptions {
        id_token_claims: vec![
            OidcIdTokenClaimRequest::EssentialAuthTime,
            OidcIdTokenClaimRequest::EssentialAcr {
                values: vec!["urn:example:loa:2".to_string()],
            },
        ],
        ..Default::default()
    };

    let valid = run_bound_case(now, options.clone(), |claims| {
        claims["auth_time"] = json!(now.unix_timestamp());
        claims["acr"] = json!("urn:example:loa:2");
    })
    .await
    .unwrap();
    assert_eq!(
        valid.authorization.matched_acr.as_deref(),
        Some("urn:example:loa:2")
    );

    for acr in [
        None,
        Some(json!("urn:example:loa:1")),
        Some(json!(["urn:example:loa:2"])),
    ] {
        let result = run_bound_case(now, options.clone(), move |claims| {
            claims["auth_time"] = json!(now.unix_timestamp());
            if let Some(acr) = acr {
                claims["acr"] = acr;
            }
        })
        .await;
        assert!(matches!(result, Err(AuthError::OidcTokenValidation(_))));
    }

    let missing_auth_time = run_bound_case(now, options, |claims| {
        claims["acr"] = json!("urn:example:loa:2");
    })
    .await;
    assert!(matches!(
        missing_auth_time,
        Err(AuthError::OidcTokenValidation(_))
    ));
}

#[tokio::test]
async fn microsoft_shaped_acrs_is_typed_bounded_and_distinct_from_acr() {
    let valid = run_validation_case(|claims, _| {
        claims["acr"] = json!("urn:standard:loa:2");
        claims["acrs"] = json!(["c1", "c2"]);
    })
    .await
    .unwrap();
    assert_eq!(valid.claims.acr.as_deref(), Some("urn:standard:loa:2"));
    assert_eq!(
        valid.claims.acrs,
        Some(vec!["c1".to_string(), "c2".to_string()])
    );
    assert!(valid.claims.amr.is_none());

    let invalid_values = vec![
        json!("c1"),
        json!({"value": "c1"}),
        json!([["c1"]]),
        json!(["c1", "c1"]),
        json!([""]),
        json!(["c1\n"]),
        json!(
            (0..=MAX_OIDC_AUTHORIZATION_VALUES)
                .map(|i| format!("c{i}"))
                .collect::<Vec<_>>()
        ),
        json!(["x".repeat(MAX_OIDC_AUTHORIZATION_VALUE_LENGTH + 1)]),
        json!(
            (0..9)
                .map(|i| format!("{i}{}", "x".repeat(255)))
                .collect::<Vec<_>>()
        ),
    ];
    for value in invalid_values {
        let result = run_validation_case(move |claims, _| claims["acrs"] = value).await;
        assert!(matches!(result, Err(AuthError::OidcTokenValidation(_))));
    }
}

#[tokio::test]
async fn bound_callback_is_single_use_under_concurrency_and_debug_is_redacted() {
    let (provider, client) = provider_and_client();
    let store = MemoryOAuthStateStore::default();
    let options = OidcAuthorizationOptions {
        max_age: Some(60),
        ..Default::default()
    };
    let request = provider
        .create_authorization_request_with_options(&store, options)
        .await
        .unwrap();
    let mut claims = valid_claims(&request.nonce);
    claims["auth_time"] = json!(OffsetDateTime::now_utc().unix_timestamp());
    claims["debug_secret"] = json!("raw-claim-secret");
    client.set_token_response(signed_id_token(claims, "rsa01"));
    let input = OidcCallbackInput::code_and_state("secret-code", request.state.clone());
    let debug = format!("{input:?}");
    assert!(!debug.contains("secret-code"));
    assert!(!debug.contains(&request.state));

    let first = tokio::spawn({
        let provider = provider.clone();
        let store = store.clone();
        let input = input.clone();
        async move { provider.handle_callback(&store, input).await }
    });
    let second = tokio::spawn({
        let provider = provider.clone();
        let store = store.clone();
        async move { provider.handle_callback(&store, input).await }
    });
    let results = [first.await.unwrap(), second.await.unwrap()];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    let outcome = results.into_iter().find_map(Result::ok).unwrap();
    let debug = format!("{outcome:?}");
    assert!(!debug.contains("opaque-provider-access-token"));
    assert!(!debug.contains(&request.nonce));
    assert!(!debug.contains(&request.code_verifier));
    assert!(!debug.contains("raw-claim-secret"));
}

#[tokio::test]
async fn successful_recent_reauthentication_does_not_imply_local_mfa() {
    let (provider, client) = provider_and_client();
    let state_store = MemoryOAuthStateStore::default();
    let identity_store = MemoryExternalIdentityStore::default();
    let auth = test_auth_service(
        MemoryUserStore::default(),
        MemoryRefreshTokenStore::default(),
    );
    let options = OidcAuthorizationOptions {
        prompt: vec![OidcPrompt::Login],
        max_age: Some(60),
        id_token_claims: vec![OidcIdTokenClaimRequest::EssentialAuthTime],
        ..Default::default()
    };
    let request = provider
        .create_authorization_request_with_options(&state_store, options)
        .await
        .unwrap();
    let mut claims = valid_claims(&request.nonce);
    claims["auth_time"] = json!(OffsetDateTime::now_utc().unix_timestamp());
    client.set_token_response(signed_id_token(claims, "rsa01"));

    let result = provider
        .login_with_callback(
            &auth,
            &state_store,
            &identity_store,
            &StaticProvisioner {
                user_id: "recent-user".to_string(),
            },
            &NoopClaimsMapper,
            OidcCallbackInput::code_and_state("auth-code", request.state),
            metadata(),
        )
        .await
        .unwrap();

    assert!(result.authorization.recent_authentication_was_enforced());
    assert!(!result.auth.user.session.mfa.satisfied);
    assert!(result.auth.user.session.assurance.is_none());
    assert!(result.auth.user.token_claims.auth_time.is_none());
}

#[tokio::test]
async fn callback_and_token_endpoint_errors_do_not_echo_provider_input() {
    let (provider, client) = provider_and_client();
    let store = MemoryOAuthStateStore::default();
    let callback_error = provider
        .handle_callback(
            &store,
            OidcCallbackInput {
                code: None,
                state: None,
                error: Some("secret-state-value".to_string()),
                error_description: Some("secret-code-and-token".to_string()),
            },
        )
        .await
        .unwrap_err();
    let displayed = callback_error.to_string();
    assert!(!displayed.contains("secret-state-value"));
    assert!(!displayed.contains("secret-code-and-token"));
    assert_eq!(callback_error.public_code(), "UNAUTHENTICATED");

    let request = provider.create_authorization_request(&store).await.unwrap();
    *client.post_response.lock().unwrap() = json!({
        "error": "secret-client-value",
        "error_description": "secret-token-value"
    });
    let token_error = provider
        .handle_callback(
            &store,
            OidcCallbackInput::code_and_state("secret-code", request.state),
        )
        .await
        .unwrap_err();
    let displayed = token_error.to_string();
    assert!(!displayed.contains("secret-client-value"));
    assert!(!displayed.contains("secret-token-value"));
    assert!(!displayed.contains("secret-code"));
}

async fn run_validation_case(
    mutate_claims: impl FnOnce(&mut JsonValue, &str),
) -> crate::AuthResult<OidcCallbackOutcome> {
    let (provider, client) = provider_and_client();
    let state_store = MemoryOAuthStateStore::default();
    let request = provider
        .create_authorization_request(&state_store)
        .await
        .unwrap();
    let mut claims = valid_claims(&request.nonce);
    mutate_claims(&mut claims, &request.nonce);
    client.set_token_response(signed_id_token(claims, "rsa01"));
    provider
        .handle_callback(
            &state_store,
            OidcCallbackInput::code_and_state("auth-code", request.state),
        )
        .await
}

async fn run_bound_case(
    now: OffsetDateTime,
    options: OidcAuthorizationOptions,
    mutate_claims: impl FnOnce(&mut JsonValue),
) -> crate::AuthResult<OidcCallbackOutcome> {
    let client = MockOidcHttpClient::new();
    let mut config = MicrosoftEntraConfig::single_tenant(TENANT_ID, CLIENT_ID, REDIRECT_URI)
        .into_oidc_provider_config()
        .unwrap();
    config.clock_skew = Duration::seconds(5);
    let provider = OidcProvider::new_with_clock(
        config,
        Arc::new(client.clone()),
        Arc::new(FixedClock::new(now)),
    )
    .unwrap();
    let store = MemoryOAuthStateStore::default();
    let request = provider
        .create_authorization_request_with_options(&store, options)
        .await?;
    let mut claims = valid_claims(&request.nonce);
    claims["iat"] = json!(now.unix_timestamp());
    claims["nbf"] = json!((now - Duration::minutes(1)).unix_timestamp());
    claims["exp"] = json!((now + Duration::minutes(10)).unix_timestamp());
    mutate_claims(&mut claims);
    client.set_token_response(signed_id_token(claims, "rsa01"));
    provider
        .handle_callback(
            &store,
            OidcCallbackInput::code_and_state("auth-code", request.state),
        )
        .await
}

fn query_pairs(url: &str) -> Vec<(String, String)> {
    url.split_once('?')
        .map(|(_, query)| query)
        .unwrap_or_default()
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| {
            (
                percent_decode_str(key).decode_utf8_lossy().into_owned(),
                percent_decode_str(value).decode_utf8_lossy().into_owned(),
            )
        })
        .collect()
}

fn query_values<'a>(pairs: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    pairs
        .iter()
        .filter_map(|(key, value)| (key == name).then_some(value.as_str()))
        .collect()
}

fn provider_and_client() -> (OidcProvider, MockOidcHttpClient) {
    let client = MockOidcHttpClient::new();
    let provider = OidcProvider::new(
        MicrosoftEntraConfig::single_tenant(TENANT_ID, CLIENT_ID, REDIRECT_URI)
            .into_oidc_provider_config()
            .unwrap(),
        Arc::new(client.clone()),
    )
    .unwrap();
    (provider, client)
}

fn generic_provider_and_client() -> (OidcProvider, MockOidcHttpClient) {
    let client = MockOidcHttpClient::new();
    let provider = OidcProvider::new(
        OidcProviderConfig::new("generic", DISCOVERY_URL, CLIENT_ID, REDIRECT_URI),
        Arc::new(client.clone()),
    )
    .unwrap();
    (provider, client)
}

async fn run_generic_validation_case(
    mutate_claims: impl FnOnce(&mut JsonValue, &str),
) -> crate::AuthResult<OidcCallbackOutcome> {
    let (provider, client) = generic_provider_and_client();
    let state_store = MemoryOAuthStateStore::default();
    let request = provider
        .create_authorization_request(&state_store)
        .await
        .unwrap();
    let mut claims = valid_claims(&request.nonce);
    mutate_claims(&mut claims, &request.nonce);
    client.set_token_response(signed_id_token(claims, "rsa01"));
    provider
        .handle_callback(
            &state_store,
            OidcCallbackInput::code_and_state("auth-code", request.state),
        )
        .await
}

fn discovery_document() -> JsonValue {
    json!({
        "issuer": ISSUER,
        "authorization_endpoint": AUTH_ENDPOINT,
        "token_endpoint": TOKEN_ENDPOINT,
        "jwks_uri": JWKS_URI
    })
}

fn jwks_document(kid: &str) -> JsonValue {
    json!({
        "keys": [
            {
                "kty": "RSA",
                "n": "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ",
                "e": "AQAB",
                "kid": kid,
                "alg": "RS256",
                "use": "sig"
            }
        ]
    })
}

fn valid_claims(nonce: &str) -> JsonValue {
    let now = OffsetDateTime::now_utc();
    json!({
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": SUBJECT,
        "exp": (now + Duration::minutes(10)).unix_timestamp(),
        "nbf": (now - Duration::minutes(1)).unix_timestamp(),
        "iat": now.unix_timestamp(),
        "nonce": nonce,
        "tid": TENANT_ID,
        "oid": OBJECT_ID,
        "email": "alice@example.test",
        "name": "Alice Example",
        "preferred_username": "alice@example.test",
        "roles": ["App.Admin"],
        "groups": ["group-1"]
    })
}

fn signed_id_token(claims: JsonValue, kid: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY.as_bytes()).unwrap(),
    )
    .unwrap()
}
