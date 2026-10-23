use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::{Value as JsonValue, json};
use time::{Duration, OffsetDateTime};

use super::oidc::{MemoryOAuthStateStore, query_pairs};
use super::provider_http::{RecordingHttpClient, bearer_token_response};
use crate::prelude::*;
use crate::{
    CLIENT_ASSERTION_TYPE_JWT_BEARER, MAX_OAUTH2_SUBJECT_LENGTH, MAX_OAUTH2_VERIFIED_EMAIL_ENTRIES,
};

const GITHUB_TOKEN: &str = "https://github.com/login/oauth/access_token";
const GITHUB_USER: &str = "https://api.github.com/user";
const GITHUB_EMAILS: &str = "https://api.github.com/user/emails";
const REDIRECT: &str = "https://app.example.test/auth/github/callback";
const PROVIDER_ACCESS_TOKEN: &str = "gho_provider-access-token";
const P256_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRnNbhOvXFlap2FIK
UBAPwlm1ReFyEpmbYNwd/ybRPfKhRANCAASZ1KyW7EZAu6s9hssYuCpgzKwrdcur
XsucriUFWbMtgHZBVWNyMjC5Upq3SaZSOfIJK6vLeo/j+7BvzyltmAJ5
-----END PRIVATE KEY-----";
const P256_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmdSsluxGQLurPYbLGLgqYMysK3XL
q17LnK4lBVmzLYB2QVVjcjIwuVKat0mmUjnyCSury3qP4/uwb88pbZgCeQ==
-----END PUBLIC KEY-----";

fn github_user() -> JsonValue {
    json!({
        "id": 583231,
        "login": "octocat",
        "name": "The Octocat",
        "avatar_url": "https://avatars.githubusercontent.com/u/583231",
        "email": "public@example.test"
    })
}

fn github_emails() -> JsonValue {
    json!([
        {"email": "secondary@example.test", "primary": false, "verified": true},
        {"email": "octocat@example.test", "primary": true, "verified": true}
    ])
}

fn github_client() -> RecordingHttpClient {
    let client = RecordingHttpClient::new(true);
    client.set_post(Ok(bearer_token_response(PROVIDER_ACCESS_TOKEN)));
    client.set_get(GITHUB_USER, Ok(github_user()));
    client.set_get(GITHUB_EMAILS, Ok(github_emails()));
    client
}

fn github_config() -> OAuth2ProviderConfig {
    OAuth2ProviderConfig::github("client id", "s:cret/+", REDIRECT)
}

fn provider_with(config: OAuth2ProviderConfig, client: &RecordingHttpClient) -> OAuth2Provider {
    OAuth2Provider::new(config, Arc::new(client.clone())).unwrap()
}

async fn start(provider: &OAuth2Provider, store: &MemoryOAuthStateStore) -> String {
    provider
        .create_authorization_request(store)
        .await
        .unwrap()
        .state
}

async fn complete(
    provider: &OAuth2Provider,
    store: &MemoryOAuthStateStore,
    state: &str,
) -> crate::AuthResult<OAuth2CallbackOutcome> {
    provider
        .handle_callback(store, OidcCallbackInput::code_and_state("auth-code", state))
        .await
}

async fn profile_for(
    config: OAuth2ProviderConfig,
    user: JsonValue,
    emails: Option<Result<JsonValue, ()>>,
) -> (crate::AuthResult<OAuth2UserProfile>, RecordingHttpClient) {
    let client = github_client();
    client.set_get(GITHUB_USER, Ok(user));
    if let Some(emails) = emails {
        client.set_get(GITHUB_EMAILS, emails);
    }
    let provider = provider_with(config, &client);
    let store = MemoryOAuthStateStore::default();
    let state = start(&provider, &store).await;
    let result = complete(&provider, &store, &state)
        .await
        .map(|outcome| outcome.profile);
    (result, client)
}

#[tokio::test]
async fn github_authorization_request_uses_pkce_and_no_oidc_parameters() {
    let client = github_client();
    let provider = provider_with(github_config(), &client);
    let store = MemoryOAuthStateStore::default();
    let request = provider.create_authorization_request(&store).await.unwrap();

    assert!(
        request
            .authorization_url
            .starts_with("https://github.com/login/oauth/authorize?")
    );
    let pairs = query_pairs(&request.authorization_url);
    let value = |name: &str| {
        pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    assert_eq!(value("client_id"), Some("client id"));
    assert_eq!(value("redirect_uri"), Some(REDIRECT));
    assert_eq!(value("response_type"), Some("code"));
    assert_eq!(value("scope"), Some("read:user user:email"));
    assert_eq!(value("state"), Some(request.state.as_str()));
    assert_eq!(value("code_challenge_method"), Some("S256"));
    assert_eq!(
        value("code_challenge"),
        Some(pkce_s256_challenge(&request.code_verifier).as_str())
    );
    assert_eq!(value("nonce"), None);
    assert_eq!(value("response_mode"), None);

    let stored = store
        .consume_oauth_state(
            "github",
            &hash_oauth_state(&request.state),
            OffsetDateTime::now_utc(),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(stored.nonce.is_empty());
    assert_eq!(stored.code_verifier, request.code_verifier);
    assert_eq!(stored.response_mode, OAuthResponseMode::Query);
    assert!(client.requests().is_empty());

    let debug = format!("{request:?}");
    assert!(!debug.contains(&request.state));
    assert!(!debug.contains(&request.code_verifier));
}

#[tokio::test]
async fn github_callback_exchanges_code_and_selects_primary_verified_email() {
    let client = github_client();
    let provider = provider_with(github_config(), &client);
    let store = MemoryOAuthStateStore::default();
    let request = provider.create_authorization_request(&store).await.unwrap();

    let outcome = complete(&provider, &store, &request.state).await.unwrap();

    let posts = client.posts();
    assert_eq!(posts.len(), 1);
    let token = &posts[0];
    assert_eq!(token.url, GITHUB_TOKEN);
    assert_eq!(token.header("Accept"), Some("application/json"));
    assert_eq!(token.header("Authorization"), None);
    assert_eq!(token.form_value("grant_type"), Some("authorization_code"));
    assert_eq!(token.form_value("code"), Some("auth-code"));
    assert_eq!(token.form_value("redirect_uri"), Some(REDIRECT));
    assert_eq!(
        token.form_value("code_verifier"),
        Some(request.code_verifier.as_str())
    );
    assert_eq!(token.form_value("client_id"), Some("client id"));
    assert_eq!(token.form_value("client_secret"), Some("s:cret/+"));

    for url in [GITHUB_USER, GITHUB_EMAILS] {
        let gets = client.gets_to(url);
        assert_eq!(gets.len(), 1, "{url}");
        assert_eq!(
            gets[0].header("Authorization"),
            Some(format!("Bearer {PROVIDER_ACCESS_TOKEN}").as_str())
        );
        assert_eq!(gets[0].header("Accept"), Some("application/json"));
    }

    let profile = &outcome.profile;
    assert_eq!(profile.provider_name, "github");
    assert_eq!(profile.subject, "583231");
    assert_eq!(profile.email.as_deref(), Some("octocat@example.test"));
    assert_eq!(profile.email_verified, Some(true));
    assert_eq!(profile.name.as_deref(), Some("The Octocat"));
    assert_eq!(
        profile.picture.as_deref(),
        Some("https://avatars.githubusercontent.com/u/583231")
    );
    assert_eq!(profile.raw["login"], "octocat");
    assert_eq!(outcome.token_response.access_token, PROVIDER_ACCESS_TOKEN);
    assert_eq!(outcome.token_response.token_type, "bearer");
    assert!(outcome.state.consumed_at.is_none());

    let debug = format!("{outcome:?}");
    assert!(!debug.contains(PROVIDER_ACCESS_TOKEN));
    assert!(!debug.contains(&request.code_verifier));
    assert!(!format!("{:?}", provider.config()).contains("s:cret"));
}

#[tokio::test]
async fn replayed_unknown_and_missing_state_are_refused_without_token_requests() {
    let client = github_client();
    let provider = provider_with(github_config(), &client);
    let store = MemoryOAuthStateStore::default();
    let state = start(&provider, &store).await;
    complete(&provider, &store, &state).await.unwrap();

    let replay = complete(&provider, &store, &state).await.unwrap_err();
    assert!(matches!(replay, AuthError::InvalidOAuthState));
    let unknown = complete(&provider, &store, "unknown-state")
        .await
        .unwrap_err();
    assert!(matches!(unknown, AuthError::InvalidOAuthState));
    let missing = provider
        .handle_callback(
            &store,
            OidcCallbackInput {
                code: Some("auth-code".to_string()),
                state: None,
                error: None,
                error_description: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(missing, AuthError::InvalidOAuthState));
    assert_eq!(client.posts().len(), 1);
    assert_eq!(replay.public_code(), "INVALID_OAUTH_STATE");
}

#[tokio::test]
async fn expired_state_is_refused_and_consumed() {
    let client = github_client();
    let clock = FixedClock::new(OffsetDateTime::now_utc());
    let provider = OAuth2Provider::new_with_clock(
        github_config(),
        Arc::new(client.clone()),
        Arc::new(clock.clone()),
    )
    .unwrap();
    let store = MemoryOAuthStateStore::default();
    let state = start(&provider, &store).await;
    clock.advance_seconds(Duration::minutes(10).whole_seconds());

    let expired = complete(&provider, &store, &state).await.unwrap_err();
    assert!(matches!(expired, AuthError::OAuthStateExpired));
    clock.advance_seconds(-60);
    let after = complete(&provider, &store, &state).await.unwrap_err();
    assert!(matches!(after, AuthError::InvalidOAuthState));
    assert!(client.posts().is_empty());
}

#[tokio::test]
async fn provider_error_and_missing_code_do_not_consume_state() {
    let client = github_client();
    let provider = provider_with(github_config(), &client);
    let store = MemoryOAuthStateStore::default();
    let state = start(&provider, &store).await;

    let denied = provider
        .handle_callback(
            &store,
            OidcCallbackInput {
                code: None,
                state: Some(state.clone()),
                error: Some("access_denied".to_string()),
                error_description: Some("provider text secret-detail".to_string()),
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(denied, AuthError::OAuthProviderError));
    assert_eq!(denied.public_code(), "UNAUTHENTICATED");
    assert!(!denied.to_string().contains("secret-detail"));

    for code in [None, Some(String::new())] {
        let missing = provider
            .handle_callback(
                &store,
                OidcCallbackInput {
                    code,
                    state: Some(state.clone()),
                    error: None,
                    error_description: None,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(missing, AuthError::OAuthCallback(_)));
        assert_eq!(missing.public_code(), "UNAUTHENTICATED");
    }
    assert!(client.posts().is_empty());
    complete(&provider, &store, &state).await.unwrap();
}

#[tokio::test]
async fn token_endpoint_failures_are_typed_and_never_echo_provider_text() {
    let cases = [
        Ok(json!({"error": "bad_verification_code", "error_description": "provider-secret-text"})),
        Ok(json!("access_token=provider-secret-text&token_type=bearer")),
        Err(()),
        Ok(json!({"token_type": "bearer"})),
        Ok(json!({"access_token": "", "token_type": "bearer"})),
        Ok(json!({"access_token": "provider-secret-text"})),
        Ok(json!({"access_token": "provider-secret-text", "token_type": "mac"})),
        Ok(
            json!({"access_token": "provider-secret-text", "token_type": "bearer", "expires_in": "soon"}),
        ),
        Ok(json!({"access_token": "provider-secret-text", "token_type": "bearer", "scope": 7})),
    ];
    for response in cases {
        let client = github_client();
        client.set_post(response.clone());
        let provider = provider_with(github_config(), &client);
        let store = MemoryOAuthStateStore::default();
        let state = start(&provider, &store).await;

        let error = complete(&provider, &store, &state).await.unwrap_err();
        assert!(
            matches!(error, AuthError::OAuthTokenExchange(_)),
            "{response:?}: {error:?}"
        );
        assert_eq!(error.public_code(), "AUTH_SERVICE_UNAVAILABLE");
        assert!(!error.to_string().contains("provider-secret-text"));
        assert!(client.gets_to(GITHUB_USER).is_empty());
        let replay = complete(&provider, &store, &state).await.unwrap_err();
        assert!(matches!(replay, AuthError::InvalidOAuthState));
    }
}

#[tokio::test]
async fn userinfo_failures_and_unusable_subjects_are_refused() {
    let (empty, _) = profile_for(github_config(), json!({}), None).await;
    assert!(matches!(empty.unwrap_err(), AuthError::OAuthMissingSubject));

    let client = github_client();
    client.set_get(GITHUB_USER, Err(()));
    let provider = provider_with(github_config(), &client);
    let store = MemoryOAuthStateStore::default();
    let state = start(&provider, &store).await;
    let error = complete(&provider, &store, &state).await.unwrap_err();
    assert!(matches!(error, AuthError::OAuthUserInfo(_)));
    assert_eq!(error.public_code(), "AUTH_SERVICE_UNAVAILABLE");

    let (not_object, _) = profile_for(github_config(), json!(["id"]), None).await;
    assert!(matches!(
        not_object.unwrap_err(),
        AuthError::OAuthUserInfo(_)
    ));

    for subject in [
        json!(null),
        json!(""),
        json!(true),
        json!(1.5),
        json!({"nested": 1}),
        json!("a\u{0000}b"),
        json!("x".repeat(MAX_OAUTH2_SUBJECT_LENGTH + 1)),
    ] {
        let (result, _) = profile_for(github_config(), json!({"id": subject}), None).await;
        let error = result.unwrap_err();
        assert!(matches!(error, AuthError::OAuthMissingSubject), "{error:?}");
        assert_eq!(error.public_code(), "UNAUTHENTICATED");
    }

    for (subject, expected) in [
        (json!(42), "42"),
        (json!(-7), "-7"),
        (json!(u64::MAX), "18446744073709551615"),
        (json!("abc-123"), "abc-123"),
    ] {
        let (result, _) = profile_for(github_config(), json!({"id": subject}), None).await;
        assert_eq!(result.unwrap().subject, expected);
    }
}

#[tokio::test]
async fn verified_email_list_selection_rules() {
    let unverified_primary = json!([
        {"email": "primary@example.test", "primary": true, "verified": false},
        {"email": "other@example.test", "primary": false, "verified": true}
    ]);
    let (profile, _) = profile_for(
        github_config(),
        github_user(),
        Some(Ok(unverified_primary.clone())),
    )
    .await;
    let profile = profile.unwrap();
    assert_eq!(profile.email.as_deref(), Some("public@example.test"));
    assert_eq!(profile.email_verified, None);

    let mut first_verified = github_config();
    let mut list = OAuth2VerifiedEmailList::primary_verified(GITHUB_EMAILS);
    list.selection = OAuth2VerifiedEmailSelection::FirstVerified;
    first_verified.verified_email_list = Some(list);
    let (profile, _) =
        profile_for(first_verified, github_user(), Some(Ok(unverified_primary))).await;
    let profile = profile.unwrap();
    assert_eq!(profile.email.as_deref(), Some("other@example.test"));
    assert_eq!(profile.email_verified, Some(true));

    let string_flags = json!([{"email": "s@example.test", "primary": "true", "verified": "true"}]);
    let (profile, _) = profile_for(github_config(), github_user(), Some(Ok(string_flags))).await;
    assert_eq!(profile.unwrap().email.as_deref(), Some("s@example.test"));

    let non_boolean = json!([{"email": "n@example.test", "primary": 1, "verified": "yes"}]);
    let (profile, _) = profile_for(github_config(), github_user(), Some(Ok(non_boolean))).await;
    assert_eq!(profile.unwrap().email_verified, None);

    let (failed, _) = profile_for(github_config(), github_user(), Some(Err(()))).await;
    assert!(matches!(failed.unwrap_err(), AuthError::OAuthUserInfo(_)));

    let (not_array, _) = profile_for(github_config(), github_user(), Some(Ok(json!({})))).await;
    assert!(matches!(
        not_array.unwrap_err(),
        AuthError::OAuthUserInfo(_)
    ));

    let too_many = JsonValue::Array(
        (0..=MAX_OAUTH2_VERIFIED_EMAIL_ENTRIES)
            .map(|index| json!({"email": format!("{index}@example.test"), "primary": true, "verified": true}))
            .collect(),
    );
    let (too_many, _) = profile_for(github_config(), github_user(), Some(Ok(too_many))).await;
    assert!(matches!(too_many.unwrap_err(), AuthError::OAuthUserInfo(_)));

    let mut wrapped = github_config();
    let mut list = OAuth2VerifiedEmailList::primary_verified(GITHUB_EMAILS);
    list.entries_pointer = Some("/data".to_string());
    wrapped.verified_email_list = Some(list);
    let (profile, _) = profile_for(
        wrapped,
        github_user(),
        Some(Ok(json!({"data": github_emails()}))),
    )
    .await;
    assert_eq!(
        profile.unwrap().email.as_deref(),
        Some("octocat@example.test")
    );
}

#[tokio::test]
async fn profile_email_verification_sources() {
    let mut pointer = github_config();
    pointer.profile.email_verification =
        OAuth2EmailVerification::Pointer("/email_verified".to_string());
    pointer.verified_email_list = None;
    for (flag, expected) in [
        (json!(true), Some(true)),
        (json!("true"), Some(true)),
        (json!(false), Some(false)),
        (json!("false"), Some(false)),
        (json!("TRUE"), None),
        (json!("yes"), None),
        (json!(1), None),
        (json!(null), None),
    ] {
        let mut user = github_user();
        user["email_verified"] = flag.clone();
        let (profile, _) = profile_for(pointer.clone(), user, None).await;
        assert_eq!(profile.unwrap().email_verified, expected, "{flag}");
    }

    let mut user = github_user();
    user["email_verified"] = json!(true);
    user["email"] = JsonValue::Null;
    let (profile, _) = profile_for(pointer.clone(), user, None).await;
    let profile = profile.unwrap();
    assert_eq!(profile.email, None);
    assert_eq!(profile.email_verified, None);

    let mut all = pointer.clone();
    all.profile.email_verification = OAuth2EmailVerification::ProviderVerifiesAll;
    let (profile, _) = profile_for(all.clone(), github_user(), None).await;
    assert_eq!(profile.unwrap().email_verified, Some(true));
    let mut no_email = github_user();
    no_email["email"] = JsonValue::Null;
    let (profile, _) = profile_for(all, no_email, None).await;
    assert_eq!(profile.unwrap().email_verified, None);

    let mut verified_profile = github_config();
    verified_profile.profile.email_verification =
        OAuth2EmailVerification::Pointer("/email_verified".to_string());
    let mut user = github_user();
    user["email_verified"] = json!(true);
    let (profile, client) = profile_for(verified_profile, user, None).await;
    assert_eq!(
        profile.unwrap().email.as_deref(),
        Some("public@example.test")
    );
    assert!(client.gets_to(GITHUB_EMAILS).is_empty());

    let (profile, client) = profile_for(github_config(), github_user(), None).await;
    assert_eq!(profile.unwrap().email_verified, Some(true));
    assert_eq!(client.gets_to(GITHUB_EMAILS).len(), 1);
}

#[tokio::test]
async fn client_secret_basic_encodes_credentials_in_the_authorization_header() {
    let client = github_client();
    let mut config = github_config();
    config.token_endpoint_auth_method = TokenEndpointAuthMethod::ClientSecretBasic;
    let provider = provider_with(config, &client);
    let store = MemoryOAuthStateStore::default();
    let state = start(&provider, &store).await;
    complete(&provider, &store, &state).await.unwrap();

    let token = &client.posts()[0];
    assert_eq!(
        token.header("Authorization"),
        Some(format!("Basic {}", STANDARD.encode("client%20id:s%3Acret%2F%2B")).as_str())
    );
    assert_eq!(token.header("Accept"), Some("application/json"));
    assert_eq!(token.form_value("client_id"), None);
    assert_eq!(token.form_value("client_secret"), None);
    assert!(token.form_value("code_verifier").is_some());
}

#[tokio::test]
async fn private_key_jwt_assertion_targets_the_token_endpoint() {
    let client = github_client();
    let clock = FixedClock::new(OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap());
    let mut config = github_config();
    config.client_secret = None;
    config.token_endpoint_auth_method = TokenEndpointAuthMethod::PrivateKeyJwt;
    config.client_jwt = Some(
        ClientJwtSigner::from_pem(
            ClientJwtAlgorithm::ES256,
            P256_PRIVATE_KEY.as_bytes(),
            ClientJwtClaims::new("client id", "client id").with_key_id("key-1"),
        )
        .unwrap(),
    );
    let provider =
        OAuth2Provider::new_with_clock(config, Arc::new(client.clone()), Arc::new(clock)).unwrap();
    let store = MemoryOAuthStateStore::default();
    let state = start(&provider, &store).await;
    complete(&provider, &store, &state).await.unwrap();

    let token = &client.posts()[0];
    assert_eq!(token.form_value("client_secret"), None);
    assert_eq!(token.form_value("client_id"), Some("client id"));
    assert_eq!(
        token.form_value("client_assertion_type"),
        Some(CLIENT_ASSERTION_TYPE_JWT_BEARER)
    );
    let assertion = token.form_value("client_assertion").unwrap();
    let header = jsonwebtoken::decode_header(assertion).unwrap();
    assert_eq!(header.alg, Algorithm::ES256);
    assert_eq!(header.kid.as_deref(), Some("key-1"));
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&[GITHUB_TOKEN]);
    validation.validate_exp = false;
    let claims = decode::<JsonValue>(
        assertion,
        &DecodingKey::from_ec_pem(P256_PUBLIC_KEY.as_bytes()).unwrap(),
        &validation,
    )
    .unwrap()
    .claims;
    assert_eq!(claims["iss"], "client id");
    assert_eq!(claims["sub"], "client id");
    assert_eq!(claims["iat"], 1_800_000_000);
    assert_eq!(claims["exp"], 1_800_000_300);
    assert!(claims["jti"].as_str().is_some_and(|jti| jti.len() >= 43));
}

type ConfigMutation = Box<dyn Fn(&mut OAuth2ProviderConfig)>;

#[test]
fn constructors_fail_closed_on_unsafe_configuration() {
    let headerless = Arc::new(RecordingHttpClient::new(false));
    let error = OAuth2Provider::new(github_config(), headerless).unwrap_err();
    assert!(matches!(error, AuthError::InvalidConfiguration(_)));

    let signer = ClientJwtSigner::from_pem(
        ClientJwtAlgorithm::ES256,
        P256_PRIVATE_KEY.as_bytes(),
        ClientJwtClaims::new("iss", "sub"),
    )
    .unwrap();
    let mutations: Vec<ConfigMutation> = vec![
        Box::new(|config| config.provider_name = " ".to_string()),
        Box::new(|config| config.client_id = String::new()),
        Box::new(|config| config.redirect_uri = String::new()),
        Box::new(|config| config.token_endpoint = "http://github.com/token".to_string()),
        Box::new(|config| config.userinfo_endpoint = "ftp://api.github.com/user".to_string()),
        Box::new(|config| config.userinfo_endpoint = "https://user@api.github.com/".to_string()),
        Box::new(|config| config.userinfo_endpoint = "https:///user".to_string()),
        Box::new(|config| config.token_endpoint = "https://github.com/ token".to_string()),
        Box::new(|config| {
            config.authorization_endpoint = "https://github.com/authorize?state=fixed".to_string()
        }),
        Box::new(|config| config.client_secret = Some(String::new())),
        Box::new(|config| config.scopes = vec!["read user".to_string()]),
        Box::new(|config| config.scopes = vec![String::new()]),
        Box::new(|config| config.state_ttl = Duration::ZERO),
        Box::new(|config| config.profile.subject_pointer = "/".to_string()),
        Box::new(|config| config.profile.subject_pointer = "id".to_string()),
        Box::new(|config| config.profile.email_pointer = Some(String::new())),
        Box::new(|config| {
            config.profile.email_verification = OAuth2EmailVerification::Pointer("x".to_string())
        }),
        Box::new(|config| {
            if let Some(list) = config.verified_email_list.as_mut() {
                list.primary_pointer = None;
            }
        }),
        Box::new(|config| {
            if let Some(list) = config.verified_email_list.as_mut() {
                list.endpoint = "http://api.github.com/user/emails".to_string();
            }
        }),
        Box::new(|config| {
            config.token_endpoint_auth_method = TokenEndpointAuthMethod::ClientSecretBasic;
            config.client_secret = None;
        }),
        Box::new(|config| {
            config.token_endpoint_auth_method = TokenEndpointAuthMethod::PrivateKeyJwt;
            config.client_secret = None;
        }),
        {
            let signer = signer.clone();
            Box::new(move |config| config.client_jwt = Some(signer.clone()))
        },
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut config = github_config();
        mutate(&mut config);
        assert!(
            matches!(
                config.validate(),
                Err(AuthError::InvalidConfiguration(_)
                    | AuthError::InvalidOidcAuthorizationOptions(_))
            ),
            "mutation {index} was accepted"
        );
    }

    let mut loopback = github_config();
    loopback.authorization_endpoint = "http://127.0.0.1:8080/authorize".to_string();
    loopback.token_endpoint = "http://localhost/token".to_string();
    loopback.userinfo_endpoint = "http://[::1]:9000/user".to_string();
    loopback.validate().unwrap();

    let mut empty_scopes = github_config();
    empty_scopes.scopes.clear();
    empty_scopes.validate().unwrap();

    let debug = format!("{signer:?}");
    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains("MIGH"));
}

#[tokio::test]
async fn oidc_and_oauth2_states_cannot_be_crossed() {
    let oauth_client = github_client();
    let oauth = provider_with(github_config(), &oauth_client);
    let store = MemoryOAuthStateStore::default();

    let oidc_state = OAuthLoginState {
        provider_name: "github".to_string(),
        state_hash: hash_oauth_state("oidc-state"),
        nonce: "nonce".to_string(),
        code_verifier: "verifier".to_string(),
        redirect_uri: REDIRECT.to_string(),
        scopes: Vec::new(),
        authorization_policy: None,
        response_mode: OAuthResponseMode::Query,
        created_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + Duration::minutes(5),
        consumed_at: None,
    };
    store.insert_oauth_state(oidc_state.clone()).await.unwrap();
    let crossed = complete(&oauth, &store, "oidc-state").await.unwrap_err();
    assert!(matches!(crossed, AuthError::InvalidOAuthState));

    let mut form_post = oidc_state;
    form_post.nonce = String::new();
    form_post.state_hash = hash_oauth_state("form-post-state");
    form_post.response_mode = OAuthResponseMode::FormPost;
    store.insert_oauth_state(form_post).await.unwrap();
    let crossed = complete(&oauth, &store, "form-post-state")
        .await
        .unwrap_err();
    assert!(matches!(crossed, AuthError::InvalidOAuthState));
    assert!(oauth_client.posts().is_empty());
}
