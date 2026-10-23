use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde_json::{Value as JsonValue, json};
use time::{Duration, OffsetDateTime};

use super::oidc::{
    CLIENT_ID, DISCOVERY_URL, ISSUER, JWKS_URI, MemoryOAuthStateStore, REDIRECT_URI,
    RSA_PRIVATE_KEY, TOKEN_ENDPOINT, discovery_document, jwks_document, query_pairs,
    signed_id_token, valid_claims,
};
use super::provider_http::RecordingHttpClient;
use crate::prelude::*;
use crate::{
    CLIENT_ASSERTION_TYPE_JWT_BEARER, DEFAULT_CLIENT_JWT_ISSUED_AT_SKEW_SECONDS,
    MAX_CLIENT_JWT_ISSUED_AT_SKEW_SECONDS, MAX_CLIENT_JWT_LIFETIME_SECONDS,
};

const APPLE_AUDIENCE: &str = "https://appleid.apple.com";
const TEAM_ID: &str = "TEAM123456";
const P256_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRnNbhOvXFlap2FIK
UBAPwlm1ReFyEpmbYNwd/ybRPfKhRANCAASZ1KyW7EZAu6s9hssYuCpgzKwrdcur
XsucriUFWbMtgHZBVWNyMjC5Upq3SaZSOfIJK6vLeo/j+7BvzyltmAJ5
-----END PRIVATE KEY-----";
const P256_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmdSsluxGQLurPYbLGLgqYMysK3XL
q17LnK4lBVmzLYB2QVVjcjIwuVKat0mmUjnyCSury3qP4/uwb88pbZgCeQ==
-----END PUBLIC KEY-----";
const P384_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDA+kjbUFnDGa1HjC4Rp
9XmdzEikpkt8sIqNBhYanha9wQCxvdnHcGrwJJ/Nhcym/8KhZANiAAQjbnWjsBxg
WXsIUAwi3C9KtLphRMA12XyBqVWRfhfgfgxxj0jbt4QqynGk9V4LMMjBs+XD1o/C
gESW0TY9a50jkPJb5+zZ3U4WDfs21u3Ef4HWKCKft5yKO9oBzFcV92s=
-----END PRIVATE KEY-----";
const RSA_N: &str = "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ";

fn oidc_client(supports_headers: bool) -> RecordingHttpClient {
    let client = RecordingHttpClient::new(supports_headers);
    client.set_get(DISCOVERY_URL, Ok(discovery_document()));
    client.set_get(JWKS_URI, Ok(jwks_document("rsa01")));
    client
}

fn token_response(id_token: String) -> JsonValue {
    json!({
        "access_token": "provider-access-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token
    })
}

fn apple_signer(lifetime: Duration) -> ClientJwtSigner {
    ClientJwtSigner::from_pem(
        ClientJwtAlgorithm::ES256,
        P256_PRIVATE_KEY.as_bytes(),
        ClientJwtClaims::new(TEAM_ID, CLIENT_ID)
            .with_key_id("APPLEKEY01")
            .with_audience(APPLE_AUDIENCE)
            .with_lifetime(lifetime),
    )
    .unwrap()
}

fn form_post_config() -> OidcProviderConfig {
    let mut config = OidcProviderConfig::new("apple", DISCOVERY_URL, CLIENT_ID, REDIRECT_URI);
    config.requested_scopes = vec!["openid".into(), "name".into(), "email".into()];
    config.response_mode = OAuthResponseMode::FormPost;
    config.client_jwt = Some(apple_signer(Duration::minutes(5)));
    config
}

fn provider(
    config: OidcProviderConfig,
    client: &RecordingHttpClient,
    clock: &FixedClock,
) -> OidcProvider {
    OidcProvider::new_with_clock(config, Arc::new(client.clone()), Arc::new(clock.clone())).unwrap()
}

fn now_clock() -> FixedClock {
    FixedClock::new(
        OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp()).unwrap(),
    )
}

async fn start_with_claims(
    provider: &OidcProvider,
    client: &RecordingHttpClient,
    store: &MemoryOAuthStateStore,
    mutate: impl FnOnce(&mut JsonValue),
) -> OidcAuthorizationRequest {
    let request = provider.create_authorization_request(store).await.unwrap();
    let mut claims = valid_claims(&request.nonce);
    mutate(&mut claims);
    client.set_post(Ok(token_response(signed_id_token(claims, "rsa01"))));
    request
}

fn form_post_input(state: &str) -> OidcCallbackInput {
    OidcCallbackInput::code_and_state("auth-code", state)
}

#[tokio::test]
async fn form_post_request_is_bound_into_state_and_completes() {
    let client = oidc_client(false);
    let clock = now_clock();
    let provider = provider(form_post_config(), &client, &clock);
    let store = MemoryOAuthStateStore::default();
    let request = start_with_claims(&provider, &client, &store, |_| {}).await;

    let pairs = query_pairs(&request.authorization_url);
    let modes: Vec<_> = pairs
        .iter()
        .filter(|(key, _)| key == "response_mode")
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(modes, vec!["form_post"]);
    assert!(
        pairs
            .iter()
            .any(|(key, value)| key == "scope" && value == "openid name email")
    );

    let outcome = provider
        .handle_callback_in_mode(
            &store,
            form_post_input(&request.state),
            OAuthResponseMode::FormPost,
        )
        .await
        .unwrap();
    assert_eq!(outcome.state.response_mode, OAuthResponseMode::FormPost);
    assert_eq!(outcome.claims.subject, super::oidc::SUBJECT);

    let replay = provider
        .handle_callback_in_mode(
            &store,
            form_post_input(&request.state),
            OAuthResponseMode::FormPost,
        )
        .await
        .unwrap_err();
    assert!(matches!(replay, AuthError::InvalidOAuthState));
    assert_eq!(client.posts().len(), 1);
}

#[tokio::test]
async fn query_delivery_of_a_form_post_flow_is_refused_without_consuming_state() {
    let client = oidc_client(false);
    let clock = now_clock();
    let provider = provider(form_post_config(), &client, &clock);
    let store = MemoryOAuthStateStore::default();
    let request = start_with_claims(&provider, &client, &store, |_| {}).await;

    let query = provider
        .handle_callback(&store, form_post_input(&request.state))
        .await
        .unwrap_err();
    assert!(matches!(query, AuthError::OidcCallback(_)));
    assert_eq!(query.public_code(), "UNAUTHENTICATED");
    assert!(client.posts().is_empty());

    provider
        .handle_callback_in_mode(
            &store,
            form_post_input(&request.state),
            OAuthResponseMode::FormPost,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn state_bound_to_one_mode_refuses_the_other_after_reconfiguration() {
    let client = oidc_client(false);
    let clock = now_clock();
    let form_post = provider(form_post_config(), &client, &clock);
    let mut query_config = form_post_config();
    query_config.response_mode = OAuthResponseMode::Query;
    let query = provider(query_config, &client, &clock);
    let store = MemoryOAuthStateStore::default();

    let form_request = start_with_claims(&form_post, &client, &store, |_| {}).await;
    let refused = query
        .handle_callback(&store, form_post_input(&form_request.state))
        .await
        .unwrap_err();
    assert!(matches!(refused, AuthError::OidcCallback(_)));

    let query_request = start_with_claims(&query, &client, &store, |_| {}).await;
    let refused = form_post
        .handle_callback_in_mode(
            &store,
            form_post_input(&query_request.state),
            OAuthResponseMode::FormPost,
        )
        .await
        .unwrap_err();
    assert!(matches!(refused, AuthError::OidcCallback(_)));
    assert!(client.posts().is_empty());

    for state in [form_request.state, query_request.state] {
        let consumed = form_post
            .handle_callback_in_mode(&store, form_post_input(&state), OAuthResponseMode::FormPost)
            .await
            .unwrap_err();
        assert!(matches!(consumed, AuthError::InvalidOAuthState));
    }
}

#[tokio::test]
async fn form_post_error_callback_and_cross_site_failures_fail_closed() {
    let client = oidc_client(false);
    let clock = now_clock();
    let provider = provider(form_post_config(), &client, &clock);
    let store = MemoryOAuthStateStore::default();
    let request = start_with_claims(&provider, &client, &store, |_| {}).await;

    let cancelled = provider
        .handle_callback_in_mode(
            &store,
            OidcCallbackInput {
                code: None,
                state: Some(request.state.clone()),
                error: Some("user_cancelled_authorize".to_string()),
                error_description: None,
            },
            OAuthResponseMode::FormPost,
        )
        .await
        .unwrap_err();
    assert!(matches!(cancelled, AuthError::OidcCallback(_)));

    for input in [
        OidcCallbackInput {
            code: Some("auth-code".to_string()),
            state: None,
            error: None,
            error_description: None,
        },
        form_post_input("forged-cross-site-state"),
    ] {
        let forged = provider
            .handle_callback_in_mode(&store, input, OAuthResponseMode::FormPost)
            .await
            .unwrap_err();
        assert!(matches!(forged, AuthError::InvalidOAuthState));
    }

    clock.advance_seconds(Duration::minutes(10).whole_seconds());
    let expired = provider
        .handle_callback_in_mode(
            &store,
            form_post_input(&request.state),
            OAuthResponseMode::FormPost,
        )
        .await
        .unwrap_err();
    assert!(matches!(expired, AuthError::OAuthStateExpired));
    assert!(client.posts().is_empty());
}

type ClaimsMutation = fn(&mut JsonValue);

#[tokio::test]
async fn form_post_flow_keeps_nonce_issuer_and_audience_checks() {
    let mutations: [(&str, ClaimsMutation); 4] = [
        ("nonce", |claims| claims["nonce"] = json!("other-nonce")),
        ("issuer", |claims| {
            claims["iss"] = json!("https://attacker.example")
        }),
        ("audience", |claims| claims["aud"] = json!("other-client")),
        ("expired", |claims| {
            claims["exp"] = json!(OffsetDateTime::now_utc().unix_timestamp() - 3600)
        }),
    ];
    for (name, mutate) in mutations {
        let client = oidc_client(false);
        let clock = now_clock();
        let provider = provider(form_post_config(), &client, &clock);
        let store = MemoryOAuthStateStore::default();
        let request = start_with_claims(&provider, &client, &store, mutate).await;
        let error = provider
            .handle_callback_in_mode(
                &store,
                form_post_input(&request.state),
                OAuthResponseMode::FormPost,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(error, AuthError::OidcTokenValidation(_)),
            "{name}: {error:?}"
        );
    }
}

#[tokio::test]
async fn oidc_refuses_states_without_a_nonce() {
    let client = oidc_client(false);
    let clock = now_clock();
    let mut config = form_post_config();
    config.response_mode = OAuthResponseMode::Query;
    let provider = provider(config, &client, &clock);
    let store = MemoryOAuthStateStore::default();
    store
        .insert_oauth_state(OAuthLoginState {
            provider_name: "apple".to_string(),
            state_hash: hash_oauth_state("oauth2-state"),
            nonce: String::new(),
            code_verifier: "verifier".to_string(),
            redirect_uri: REDIRECT_URI.to_string(),
            scopes: Vec::new(),
            authorization_policy: None,
            response_mode: OAuthResponseMode::Query,
            created_at: clock.now(),
            expires_at: clock.now() + Duration::minutes(5),
            consumed_at: None,
        })
        .await
        .unwrap();
    client.set_post(Ok(token_response(signed_id_token(
        valid_claims(""),
        "rsa01",
    ))));
    let error = provider
        .handle_callback(&store, form_post_input("oauth2-state"))
        .await
        .unwrap_err();
    assert!(matches!(error, AuthError::InvalidOAuthState));
    assert!(client.posts().is_empty());
}

fn decode_client_jwt(token: &str, now: i64) -> Result<JsonValue, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&[APPLE_AUDIENCE]);
    validation.set_issuer(&[TEAM_ID]);
    validation.set_required_spec_claims(&["iss", "sub", "aud", "iat", "exp"]);
    validation.leeway = 0;
    validation.validate_exp = false;
    let claims = decode::<JsonValue>(
        token,
        &DecodingKey::from_ec_pem(P256_PUBLIC_KEY.as_bytes()).unwrap(),
        &validation,
    )?
    .claims;
    if claims["exp"].as_i64().unwrap() <= now {
        return Err(ErrorKind::ExpiredSignature.into());
    }
    Ok(claims)
}

#[tokio::test]
async fn signed_client_secret_is_fresh_verifiable_and_short_lived() {
    let client = oidc_client(false);
    let clock = now_clock();
    let lifetime = Duration::days(180);
    let mut config = form_post_config();
    config.client_jwt = Some(apple_signer(lifetime));
    let provider = provider(config, &client, &clock);
    let store = MemoryOAuthStateStore::default();

    let request = start_with_claims(&provider, &client, &store, |_| {}).await;
    provider
        .handle_callback_in_mode(
            &store,
            form_post_input(&request.state),
            OAuthResponseMode::FormPost,
        )
        .await
        .unwrap();
    let first = client.posts()[0].clone();
    assert_eq!(first.url, TOKEN_ENDPOINT);
    assert_eq!(first.form_value("client_id"), Some(CLIENT_ID));
    assert_eq!(first.form_value("client_assertion"), None);
    let secret = first.form_value("client_secret").unwrap().to_string();

    let header = decode_header(&secret).unwrap();
    assert_eq!(header.alg, Algorithm::ES256);
    assert_eq!(header.kid.as_deref(), Some("APPLEKEY01"));
    let signed_at = clock.now().unix_timestamp();
    let issued_at = signed_at - DEFAULT_CLIENT_JWT_ISSUED_AT_SKEW_SECONDS;
    let claims = decode_client_jwt(&secret, signed_at).unwrap();
    let mut names: Vec<_> = claims.as_object().unwrap().keys().cloned().collect();
    names.sort();
    assert_eq!(names, vec!["aud", "exp", "iat", "iss", "sub"]);
    assert_eq!(claims["iss"], TEAM_ID);
    assert_eq!(claims["sub"], CLIENT_ID);
    assert_eq!(claims["aud"], APPLE_AUDIENCE);
    assert_eq!(claims["iat"], issued_at);
    assert_eq!(
        claims["exp"].as_i64().unwrap() - issued_at,
        lifetime.whole_seconds()
    );

    let expired = decode_client_jwt(&secret, issued_at + lifetime.whole_seconds()).unwrap_err();
    assert!(matches!(expired.kind(), ErrorKind::ExpiredSignature));

    let wrong_key = decode::<JsonValue>(
        &secret,
        &DecodingKey::from_rsa_components(RSA_N, "AQAB").unwrap(),
        &Validation::new(Algorithm::RS256),
    );
    assert!(wrong_key.is_err());

    clock.advance_seconds(lifetime.whole_seconds() + 1);
    let request = provider.create_authorization_request(&store).await.unwrap();
    let mut claims = valid_claims(&request.nonce);
    let now = clock.now().unix_timestamp();
    claims["iat"] = json!(now);
    claims["nbf"] = json!(now - 60);
    claims["exp"] = json!(now + 600);
    client.set_post(Ok(token_response(signed_id_token(claims, "rsa01"))));
    let result = provider
        .handle_callback_in_mode(
            &store,
            form_post_input(&request.state),
            OAuthResponseMode::FormPost,
        )
        .await;
    assert!(
        !matches!(result, Err(AuthError::OidcTokenExchange(_))),
        "{result:?}"
    );
    let second = client.posts()[1]
        .form_value("client_secret")
        .unwrap()
        .to_string();
    assert_ne!(second, secret);
    let reissued = decode_client_jwt(&second, clock.now().unix_timestamp()).unwrap();
    assert_eq!(
        reissued["iat"],
        clock.now().unix_timestamp() - DEFAULT_CLIENT_JWT_ISSUED_AT_SKEW_SECONDS
    );
}

#[tokio::test]
async fn private_key_jwt_and_basic_client_authentication_for_oidc() {
    let client = oidc_client(true);
    let clock = now_clock();
    let mut config = OidcProviderConfig::new("generic", DISCOVERY_URL, CLIENT_ID, REDIRECT_URI);
    config.token_endpoint_auth_method = TokenEndpointAuthMethod::PrivateKeyJwt;
    config.client_jwt = Some(
        ClientJwtSigner::from_pem(
            ClientJwtAlgorithm::RS256,
            RSA_PRIVATE_KEY.as_bytes(),
            ClientJwtClaims::new(CLIENT_ID, CLIENT_ID),
        )
        .unwrap(),
    );
    let jwt_provider = provider(config, &client, &clock);
    let store = MemoryOAuthStateStore::default();
    for _ in 0..2 {
        let request = start_with_claims(&jwt_provider, &client, &store, |_| {}).await;
        jwt_provider
            .handle_callback(&store, form_post_input(&request.state))
            .await
            .unwrap();
    }
    let posts = client.posts();
    let mut jtis = Vec::new();
    for post in &posts {
        assert!(post.headers.is_empty());
        assert_eq!(post.form_value("client_secret"), None);
        assert_eq!(
            post.form_value("client_assertion_type"),
            Some(CLIENT_ASSERTION_TYPE_JWT_BEARER)
        );
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[TOKEN_ENDPOINT]);
        validation.set_issuer(&[CLIENT_ID]);
        let claims = decode::<JsonValue>(
            post.form_value("client_assertion").unwrap(),
            &DecodingKey::from_rsa_components(RSA_N, "AQAB").unwrap(),
            &validation,
        )
        .unwrap()
        .claims;
        assert_eq!(claims["sub"], CLIENT_ID);
        jtis.push(claims["jti"].as_str().unwrap().to_string());
    }
    assert_ne!(jtis[0], jtis[1]);

    let basic_client = oidc_client(true);
    let mut config = OidcProviderConfig::new("generic", DISCOVERY_URL, CLIENT_ID, REDIRECT_URI);
    config.client_secret = Some("static secret".to_string());
    config.token_endpoint_auth_method = TokenEndpointAuthMethod::ClientSecretBasic;
    let basic = provider(config.clone(), &basic_client, &clock);
    let request = start_with_claims(&basic, &basic_client, &store, |_| {}).await;
    basic
        .handle_callback(&store, form_post_input(&request.state))
        .await
        .unwrap();
    let post = &basic_client.posts()[0];
    assert_eq!(
        post.header("Authorization"),
        Some(format!("Basic {}", STANDARD.encode("client-id:static%20secret")).as_str())
    );
    assert_eq!(post.header("Accept"), Some("application/json"));
    assert_eq!(post.form_value("client_id"), None);
    assert_eq!(post.form_value("client_secret"), None);
    assert!(!format!("{config:?}").contains("static secret"));

    let Err(headerless) = OidcProvider::new(config, Arc::new(oidc_client(false))) else {
        panic!("client_secret_basic accepted a header-less HTTP client");
    };
    assert!(matches!(headerless, AuthError::InvalidConfiguration(_)));
}

#[test]
fn client_jwt_configuration_fails_closed() {
    let claims = || ClientJwtClaims::new(TEAM_ID, CLIENT_ID);
    for (algorithm, pem) in [
        (ClientJwtAlgorithm::ES256, P384_PRIVATE_KEY),
        (ClientJwtAlgorithm::ES384, P256_PRIVATE_KEY),
        (ClientJwtAlgorithm::ES256, RSA_PRIVATE_KEY),
        (ClientJwtAlgorithm::RS256, P256_PRIVATE_KEY),
        (ClientJwtAlgorithm::ES256, "not a key"),
    ] {
        let error = ClientJwtSigner::from_pem(algorithm, pem.as_bytes(), claims()).unwrap_err();
        assert!(
            matches!(error, AuthError::InvalidConfiguration(_)),
            "{algorithm:?}"
        );
        assert!(!error.to_string().contains("MIG"));
    }
    ClientJwtSigner::from_pem(
        ClientJwtAlgorithm::ES384,
        P384_PRIVATE_KEY.as_bytes(),
        claims(),
    )
    .unwrap();
    ClientJwtSigner::from_pem(
        ClientJwtAlgorithm::PS256,
        RSA_PRIVATE_KEY.as_bytes(),
        claims(),
    )
    .unwrap();

    for bad in [
        claims().with_lifetime(Duration::ZERO),
        claims().with_lifetime(Duration::seconds(-1)),
        claims().with_lifetime(Duration::seconds(MAX_CLIENT_JWT_LIFETIME_SECONDS + 1)),
        claims().with_lifetime(Duration::milliseconds(500)),
        claims().with_lifetime(Duration::seconds(30)),
        claims().with_lifetime(Duration::seconds(1)),
        claims().with_issued_at_skew(Duration::seconds(-1)),
        claims().with_issued_at_skew(Duration::seconds(MAX_CLIENT_JWT_ISSUED_AT_SKEW_SECONDS + 1)),
        claims().with_audience(" "),
        claims().with_key_id(""),
        ClientJwtClaims::new("", CLIENT_ID),
        ClientJwtClaims::new(TEAM_ID, " "),
    ] {
        let error =
            ClientJwtSigner::from_pem(ClientJwtAlgorithm::ES256, P256_PRIVATE_KEY.as_bytes(), bad)
                .unwrap_err();
        assert!(matches!(error, AuthError::InvalidConfiguration(_)));
    }
    ClientJwtSigner::from_pem(
        ClientJwtAlgorithm::ES256,
        P256_PRIVATE_KEY.as_bytes(),
        claims().with_lifetime(Duration::seconds(MAX_CLIENT_JWT_LIFETIME_SECONDS)),
    )
    .unwrap();
    for accepted in [
        claims().with_lifetime(Duration::seconds(31)),
        claims()
            .with_lifetime(Duration::seconds(1))
            .with_issued_at_skew(Duration::ZERO),
        claims()
            .with_lifetime(Duration::seconds(MAX_CLIENT_JWT_ISSUED_AT_SKEW_SECONDS + 1))
            .with_issued_at_skew(Duration::seconds(MAX_CLIENT_JWT_ISSUED_AT_SKEW_SECONDS)),
    ] {
        ClientJwtSigner::from_pem(
            ClientJwtAlgorithm::ES256,
            P256_PRIVATE_KEY.as_bytes(),
            accepted,
        )
        .unwrap();
    }
    let legacy_claims: ClientJwtClaims = serde_json::from_value(json!({
        "key_id": null,
        "issuer": TEAM_ID,
        "subject": CLIENT_ID,
        "audience": null,
        "lifetime": serde_json::to_value(Duration::minutes(5)).unwrap()
    }))
    .unwrap();
    assert_eq!(
        legacy_claims.issued_at_skew,
        Duration::seconds(DEFAULT_CLIENT_JWT_ISSUED_AT_SKEW_SECONDS)
    );

    let signer = apple_signer(Duration::minutes(5));
    let mut both = form_post_config();
    both.client_secret = Some("static".to_string());
    assert!(matches!(
        both.validate(),
        Err(AuthError::InvalidConfiguration(_))
    ));
    let mut missing = OidcProviderConfig::new("generic", DISCOVERY_URL, CLIENT_ID, REDIRECT_URI);
    missing.token_endpoint_auth_method = TokenEndpointAuthMethod::PrivateKeyJwt;
    assert!(matches!(
        missing.validate(),
        Err(AuthError::InvalidConfiguration(_))
    ));
    missing.token_endpoint_auth_method = TokenEndpointAuthMethod::ClientSecretBasic;
    assert!(matches!(
        missing.validate(),
        Err(AuthError::InvalidConfiguration(_))
    ));
    missing.client_jwt = Some(signer.clone());
    missing.validate().unwrap();

    let debug = format!("{:?}", form_post_config());
    assert!(debug.contains("[redacted]"));
    assert!(!debug.contains("MIGH"));

    let serialized = serde_json::to_value(form_post_config()).unwrap();
    assert!(serialized.get("client_jwt").is_none());
    assert_eq!(serialized["response_mode"], "form_post");
    let restored: OidcProviderConfig = serde_json::from_value(serialized).unwrap();
    assert!(restored.client_jwt.is_none());
    let mut legacy = serde_json::to_value(OidcProviderConfig::new(
        "generic",
        DISCOVERY_URL,
        CLIENT_ID,
        REDIRECT_URI,
    ))
    .unwrap();
    let object = legacy.as_object_mut().unwrap();
    object.remove("response_mode");
    object.remove("token_endpoint_auth_method");
    let legacy: OidcProviderConfig = serde_json::from_value(legacy).unwrap();
    assert_eq!(legacy.response_mode, OAuthResponseMode::Query);
    assert_eq!(
        legacy.token_endpoint_auth_method,
        TokenEndpointAuthMethod::ClientSecretPost
    );
}

#[tokio::test]
async fn email_verified_accepts_booleans_and_exact_strings_only() {
    for (value, expected) in [
        (Some(json!(true)), Some(true)),
        (Some(json!(false)), Some(false)),
        (Some(json!("true")), Some(true)),
        (Some(json!("false")), Some(false)),
        (Some(json!("True")), None),
        (Some(json!("1")), None),
        (Some(json!(1)), None),
        (Some(json!(null)), None),
        (Some(json!(["true"])), None),
        (None, None),
    ] {
        let client = oidc_client(false);
        let clock = now_clock();
        let mut config = OidcProviderConfig::new("generic", DISCOVERY_URL, CLIENT_ID, REDIRECT_URI);
        config.allowed_issuers = vec![ISSUER.to_string()];
        let provider = provider(config, &client, &clock);
        let store = MemoryOAuthStateStore::default();
        let request = start_with_claims(&provider, &client, &store, |claims| {
            if let Some(value) = value.clone() {
                claims["email_verified"] = value;
            }
        })
        .await;
        let outcome = provider
            .handle_callback(&store, form_post_input(&request.state))
            .await
            .unwrap();
        assert_eq!(outcome.claims.email_verified, expected, "{value:?}");
    }
}

#[test]
fn legacy_state_records_deserialize_as_query_mode() {
    let now = OffsetDateTime::now_utc();
    let state = OAuthLoginState {
        provider_name: "apple".to_string(),
        state_hash: hash_oauth_state("state"),
        nonce: "nonce".to_string(),
        code_verifier: "verifier".to_string(),
        redirect_uri: REDIRECT_URI.to_string(),
        scopes: Vec::new(),
        authorization_policy: None,
        response_mode: OAuthResponseMode::Query,
        created_at: now,
        expires_at: now,
        consumed_at: None,
    };
    let query = serde_json::to_value(&state).unwrap();
    assert!(query.get("response_mode").is_none());
    let restored: OAuthLoginState = serde_json::from_value(query).unwrap();
    assert_eq!(restored.response_mode, OAuthResponseMode::Query);

    let form_post = OAuthLoginState {
        response_mode: OAuthResponseMode::FormPost,
        ..state
    };
    let value = serde_json::to_value(&form_post).unwrap();
    assert_eq!(value["response_mode"], "form_post");
    let restored: OAuthLoginState = serde_json::from_value(value).unwrap();
    assert_eq!(restored.response_mode, OAuthResponseMode::FormPost);
}
