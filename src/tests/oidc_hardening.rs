//! OIDC and OAuth 2.0 client hardening: local account state at login,
//! discovery and endpoint policy, Entra key issuers, configuration bounds and
//! client assertions.

use std::sync::Arc;

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::{Value as JsonValue, json};
use time::Duration;

use super::oidc::{
    CLIENT_ID, DISCOVERY_URL, ISSUER, JWKS_URI, MemoryExternalIdentityStore, MemoryOAuthStateStore,
    REDIRECT_URI, RSA_PRIVATE_KEY, StaticProvisioner, TENANT_ID, TOKEN_ENDPOINT,
    callback_with_code, discovery_document, jwks_document, signed_id_token, valid_claims,
};
use super::provider_http::{RecordingHttpClient, bearer_token_response};
use super::{MemoryRefreshTokenStore, MemoryUserStore, metadata, stored_user, test_auth_service};
use crate::prelude::*;

const OTHER_TENANT_ID: &str = "33333333-3333-3333-3333-333333333333";
const ORGANIZATIONS_DISCOVERY_URL: &str =
    "https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration";
const ORGANIZATIONS_JWKS_URI: &str =
    "https://login.microsoftonline.com/organizations/discovery/v2.0/keys";
const ENTRA_TEMPLATED_ISSUER: &str = "https://login.microsoftonline.com/{tenantid}/v2.0";
const RSA_N: &str = "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ";
const GITHUB_USER: &str = "https://api.github.com/user";
const GITHUB_EMAILS: &str = "https://api.github.com/user/emails";
const GITHUB_REDIRECT: &str = "https://app.example.test/auth/github/callback";

fn oidc_client() -> RecordingHttpClient {
    let client = RecordingHttpClient::new(true);
    client.set_get(DISCOVERY_URL, Ok(discovery_document()));
    client.set_get(JWKS_URI, Ok(jwks_document("rsa01")));
    client
}

fn entra_provider(client: &RecordingHttpClient) -> OidcProvider {
    OidcProvider::new(
        MicrosoftEntraConfig::single_tenant(TENANT_ID, CLIENT_ID, REDIRECT_URI)
            .into_oidc_provider_config()
            .unwrap(),
        Arc::new(client.clone()),
    )
    .unwrap()
}

fn token_response(id_token: String) -> JsonValue {
    json!({
        "access_token": "provider-access-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token
    })
}

async fn oidc_login(
    users: MemoryUserStore,
) -> (
    crate::AuthResult<OidcLoginResult>,
    MemoryExternalIdentityStore,
) {
    let client = oidc_client();
    let provider = entra_provider(&client);
    let auth = test_auth_service(users, MemoryRefreshTokenStore::default());
    let state_store = MemoryOAuthStateStore::default();
    let identities = MemoryExternalIdentityStore::default();
    let request = provider
        .create_authorization_request(&state_store)
        .await
        .unwrap();
    client.set_post(Ok(token_response(signed_id_token(
        valid_claims(&request.nonce),
        "rsa01",
    ))));
    let result = provider
        .login_with_callback(
            &auth,
            &state_store,
            &identities,
            &StaticProvisioner {
                user_id: "local-user".to_string(),
            },
            &NoopClaimsMapper,
            callback_with_code(&request, "auth-code"),
            metadata(),
        )
        .await;
    (result, identities)
}

fn users_with(disabled: bool) -> MemoryUserStore {
    let users = MemoryUserStore::default();
    let auth = test_auth_service(users.clone(), MemoryRefreshTokenStore::default());
    let mut user = stored_user(&auth, "local-user", "alice@example.test", "password");
    user.disabled = disabled;
    users.insert(user);
    users
}

#[tokio::test]
async fn oidc_login_refuses_a_disabled_local_user() {
    let (result, identities) = oidc_login(users_with(true)).await;
    assert!(matches!(result, Err(AuthError::UserDisabled)));
    assert!(identities.identities.lock().unwrap().is_empty());

    let (enabled, _) = oidc_login(users_with(false)).await;
    assert_eq!(enabled.unwrap().auth.user.user_id, "local-user");
}

#[tokio::test]
async fn oidc_login_refuses_a_missing_local_user() {
    let (result, identities) = oidc_login(MemoryUserStore::default()).await;
    assert!(matches!(result, Err(AuthError::ExternalLoginRejected(_))));
    assert_eq!(
        result.unwrap_err().public_code(),
        "FORBIDDEN",
        "a missing user maps to a stable public code"
    );
    assert!(identities.identities.lock().unwrap().is_empty());
}

fn generic_config(discovery_url: &str) -> OidcProviderConfig {
    OidcProviderConfig::new("generic", discovery_url, CLIENT_ID, REDIRECT_URI)
}

#[test]
fn oidc_configuration_requires_https_discovery_and_redirect_uri() {
    for discovery_url in [
        "http://idp.example.test/.well-known/openid-configuration",
        "ftp://idp.example.test/.well-known/openid-configuration",
        "idp.example.test/.well-known/openid-configuration",
        "https://user@idp.example.test/.well-known/openid-configuration",
    ] {
        assert!(
            matches!(
                generic_config(discovery_url).validate(),
                Err(AuthError::InvalidConfiguration(_))
            ),
            "{discovery_url} was accepted"
        );
    }
    generic_config("http://localhost:8080/.well-known/openid-configuration")
        .validate()
        .unwrap();

    for redirect_uri in [
        "/auth/callback",
        "http://app.example.test/callback",
        "https://app.example.test/callback#fragment",
        "javascript:alert(1)",
    ] {
        let mut config = generic_config(DISCOVERY_URL);
        config.redirect_uri = redirect_uri.to_string();
        assert!(
            matches!(config.validate(), Err(AuthError::InvalidConfiguration(_))),
            "{redirect_uri} was accepted"
        );
    }
    let mut loopback = generic_config(DISCOVERY_URL);
    loopback.redirect_uri = "http://127.0.0.1:3000/callback".to_string();
    loopback.validate().unwrap();
}

async fn discovery_result(document: JsonValue) -> crate::AuthResult<OidcDiscoveryDocument> {
    let client = oidc_client();
    client.set_get(DISCOVERY_URL, Ok(document));
    OidcProvider::new(generic_config(DISCOVERY_URL), Arc::new(client))
        .unwrap()
        .discover()
        .await
}

#[tokio::test]
async fn oidc_discovery_refuses_insecure_endpoints() {
    discovery_result(discovery_document()).await.unwrap();
    for field in [
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "userinfo_endpoint",
    ] {
        let mut document = discovery_document();
        document[field] = json!("http://idp.example.test/endpoint");
        assert!(
            matches!(
                discovery_result(document).await,
                Err(AuthError::OidcDiscovery(_))
            ),
            "insecure {field} was accepted"
        );
    }
}

#[tokio::test]
async fn oidc_discovery_requires_the_configured_issuer_exactly() {
    for issuer in [
        "https://attacker.example.test",
        "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111",
        "https://LOGIN.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0",
        "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0//",
        "",
    ] {
        let mut document = discovery_document();
        document["issuer"] = json!(issuer);
        assert!(
            matches!(
                discovery_result(document).await,
                Err(AuthError::OidcDiscovery(_))
            ),
            "issuer {issuer:?} was accepted"
        );
    }

    // A derived issuer is the discovery prefix with or without one trailing
    // slash (OIDC Discovery section 4.1 strips it before appending the path).
    let mut document = discovery_document();
    document["issuer"] = json!(format!("{ISSUER}/"));
    discovery_result(document).await.unwrap();

    // A configured issuer is compared exactly.
    let client = oidc_client();
    let mut document = discovery_document();
    document["issuer"] = json!(format!("{ISSUER}/"));
    client.set_get(DISCOVERY_URL, Ok(document));
    let mut config = generic_config(DISCOVERY_URL);
    config.issuer = Some(ISSUER.to_string());
    assert!(matches!(
        OidcProvider::new(config, Arc::new(client))
            .unwrap()
            .discover()
            .await,
        Err(AuthError::OidcDiscovery(_))
    ));

    // A discovery URL that is not an issuer's well-known URL needs an issuer.
    let mut config = generic_config("https://idp.example.test/discovery.json");
    assert!(matches!(
        config.validate(),
        Err(AuthError::InvalidConfiguration(_))
    ));
    config.issuer = Some("https://idp.example.test".to_string());
    config.validate().unwrap();
}

fn organizations_client(key_issuer: Option<&str>) -> RecordingHttpClient {
    let client = RecordingHttpClient::new(true);
    client.set_get(
        ORGANIZATIONS_DISCOVERY_URL,
        Ok(json!({
            "issuer": ENTRA_TEMPLATED_ISSUER,
            "authorization_endpoint": "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize",
            "token_endpoint": "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
            "jwks_uri": ORGANIZATIONS_JWKS_URI
        })),
    );
    let mut jwks = jwks_document("rsa01");
    if let Some(key_issuer) = key_issuer {
        jwks["keys"][0]["issuer"] = json!(key_issuer);
    }
    client.set_get(ORGANIZATIONS_JWKS_URI, Ok(jwks));
    client
}

async fn organizations_callback(
    key_issuer: Option<&str>,
) -> crate::AuthResult<OidcCallbackOutcome> {
    let client = organizations_client(key_issuer);
    let provider = OidcProvider::new(
        MicrosoftEntraConfig::organizations(CLIENT_ID, REDIRECT_URI)
            .into_oidc_provider_config()
            .unwrap(),
        Arc::new(client.clone()),
    )
    .unwrap();
    let store = MemoryOAuthStateStore::default();
    let request = provider.create_authorization_request(&store).await.unwrap();
    client.set_post(Ok(token_response(signed_id_token(
        valid_claims(&request.nonce),
        "rsa01",
    ))));
    provider
        .handle_callback(&store, callback_with_code(&request, "auth-code"))
        .await
}

#[tokio::test]
async fn entra_multi_tenant_validates_the_signing_key_issuer() {
    let other_tenant = format!("https://login.microsoftonline.com/{OTHER_TENANT_ID}/v2.0");
    assert!(matches!(
        organizations_callback(Some(&other_tenant)).await,
        Err(AuthError::OidcTokenValidation(_))
    ));
    assert!(matches!(
        organizations_callback(Some("https://sts.windows.net/{tenantid}/")).await,
        Err(AuthError::OidcTokenValidation(_))
    ));

    let outcome = organizations_callback(Some(ENTRA_TEMPLATED_ISSUER))
        .await
        .unwrap();
    assert_eq!(outcome.claims.issuer, ISSUER);
    organizations_callback(Some(ISSUER)).await.unwrap();
    // Keys without issuer metadata keep the token-issuer template check only.
    organizations_callback(None).await.unwrap();
}

#[test]
fn allowed_id_token_algorithms_must_share_one_key_family() {
    for algorithms in [
        vec!["RS256", "ES256"],
        vec!["PS256", "EdDSA"],
        vec!["HS256"],
        vec!["none"],
        vec!["RS256", "unknown"],
    ] {
        let mut config = generic_config(DISCOVERY_URL);
        config.allowed_id_token_algs = algorithms.iter().map(|alg| alg.to_string()).collect();
        assert!(
            matches!(config.validate(), Err(AuthError::InvalidConfiguration(_))),
            "{algorithms:?} was accepted"
        );
    }
    for algorithms in [vec!["RS256", "PS256", "RS512"], vec!["ES256", "ES384"]] {
        let mut config = generic_config(DISCOVERY_URL);
        config.allowed_id_token_algs = algorithms.iter().map(|alg| alg.to_string()).collect();
        config.validate().unwrap();
    }
}

#[test]
fn state_ttl_is_bounded_for_both_providers() {
    let mut oidc = generic_config(DISCOVERY_URL);
    oidc.state_ttl = Duration::days(1);
    assert!(matches!(
        oidc.validate(),
        Err(AuthError::InvalidConfiguration(_))
    ));
    oidc.state_ttl = Duration::hours(1);
    oidc.validate().unwrap();

    let mut oauth2 = OAuth2ProviderConfig::github("client", "secret", GITHUB_REDIRECT);
    oauth2.state_ttl = Duration::days(1);
    assert!(matches!(
        oauth2.validate(),
        Err(AuthError::InvalidConfiguration(_))
    ));
    oauth2.state_ttl = Duration::hours(1);
    oauth2.validate().unwrap();
}

#[test]
fn oauth2_redirect_uri_must_be_an_absolute_https_url() {
    for redirect_uri in [
        "/auth/github/callback",
        "http://app.example.test/callback",
        "https://app.example.test/callback#fragment",
    ] {
        let config = OAuth2ProviderConfig::github("client", "secret", redirect_uri);
        assert!(
            matches!(config.validate(), Err(AuthError::InvalidConfiguration(_))),
            "{redirect_uri} was accepted"
        );
    }
    OAuth2ProviderConfig::github("client", "secret", "http://localhost:3000/callback")
        .validate()
        .unwrap();
}

fn github_client(token: JsonValue, user: JsonValue) -> RecordingHttpClient {
    let client = RecordingHttpClient::new(true);
    client.set_post(Ok(token));
    client.set_get(GITHUB_USER, Ok(user));
    client.set_get(GITHUB_EMAILS, Ok(json!([])));
    client
}

async fn github_callback(client: &RecordingHttpClient) -> crate::AuthResult<OAuth2CallbackOutcome> {
    let provider = OAuth2Provider::new(
        OAuth2ProviderConfig::github("client", "secret", GITHUB_REDIRECT),
        Arc::new(client.clone()),
    )
    .unwrap();
    let store = MemoryOAuthStateStore::default();
    let request = provider.create_authorization_request(&store).await.unwrap();
    provider
        .handle_callback(
            &store,
            OidcCallbackInput::code_and_state("auth-code", &request.state)
                .with_browser_binding(request.browser_binding.unwrap()),
        )
        .await
}

#[tokio::test]
async fn negative_expires_in_is_refused_by_both_providers() {
    let mut token = bearer_token_response("gho_token");
    token["expires_in"] = json!(-1);
    let client = github_client(token, json!({"id": 1}));
    assert!(matches!(
        github_callback(&client).await,
        Err(AuthError::OAuthTokenExchange(_))
    ));

    let client = oidc_client();
    let provider = entra_provider(&client);
    let store = MemoryOAuthStateStore::default();
    let request = provider.create_authorization_request(&store).await.unwrap();
    let mut response = token_response(signed_id_token(valid_claims(&request.nonce), "rsa01"));
    response["expires_in"] = json!(-60);
    client.set_post(Ok(response));
    assert!(matches!(
        provider
            .handle_callback(&store, callback_with_code(&request, "auth-code"),)
            .await,
        Err(AuthError::OidcTokenExchange(_))
    ));
}

#[tokio::test]
async fn oauth2_profile_values_are_length_bounded() {
    let long_email = format!("{}@example.test", "a".repeat(400));
    let client = github_client(
        bearer_token_response("gho_token"),
        json!({
            "id": 1,
            "email": long_email,
            "name": "n".repeat(4096),
            "avatar_url": format!("https://avatars.example.test/{}", "p".repeat(4096)),
        }),
    );
    let profile = github_callback(&client).await.unwrap().profile;
    assert_eq!(profile.email, None);
    assert_eq!(profile.email_verified, None);
    assert_eq!(profile.name, None);
    assert_eq!(profile.picture, None);

    let client = github_client(
        bearer_token_response("gho_token"),
        json!({"id": 1, "name": "The Octocat", "email": "octocat@example.test"}),
    );
    let profile = github_callback(&client).await.unwrap().profile;
    assert_eq!(profile.name.as_deref(), Some("The Octocat"));
    assert_eq!(profile.email.as_deref(), Some("octocat@example.test"));
}

fn rsa_signer(claims: ClientJwtClaims) -> crate::AuthResult<ClientJwtSigner> {
    ClientJwtSigner::from_pem(
        ClientJwtAlgorithm::RS256,
        RSA_PRIVATE_KEY.as_bytes(),
        claims,
    )
}

fn private_key_jwt_config(claims: ClientJwtClaims) -> OidcProviderConfig {
    let mut config = generic_config(DISCOVERY_URL);
    config.token_endpoint_auth_method = TokenEndpointAuthMethod::PrivateKeyJwt;
    config.client_jwt = Some(rsa_signer(claims).unwrap());
    config
}

#[tokio::test]
async fn private_key_jwt_audience_defaults_to_the_issuer() {
    let client = oidc_client();
    let provider = OidcProvider::new(
        private_key_jwt_config(ClientJwtClaims::new(CLIENT_ID, CLIENT_ID)),
        Arc::new(client.clone()),
    )
    .unwrap();
    let store = MemoryOAuthStateStore::default();
    let request = provider.create_authorization_request(&store).await.unwrap();
    client.set_post(Ok(token_response(signed_id_token(
        valid_claims(&request.nonce),
        "rsa01",
    ))));
    provider
        .handle_callback(&store, callback_with_code(&request, "auth-code"))
        .await
        .unwrap();

    let post = &client.posts()[0];
    assert_eq!(post.url, TOKEN_ENDPOINT);
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[ISSUER]);
    validation.set_issuer(&[CLIENT_ID]);
    let claims = decode::<JsonValue>(
        post.form_value("client_assertion").unwrap(),
        &DecodingKey::from_rsa_components(RSA_N, "AQAB").unwrap(),
        &validation,
    )
    .unwrap()
    .claims;
    assert_eq!(claims["aud"], ISSUER);
    assert_eq!(claims["sub"], CLIENT_ID);
    assert!(claims.get("nbf").is_none());
}

#[test]
fn private_key_jwt_requires_client_id_issuer_subject_and_a_short_lifetime() {
    for claims in [
        ClientJwtClaims::new("other", CLIENT_ID),
        ClientJwtClaims::new(CLIENT_ID, "other"),
        ClientJwtClaims::new(CLIENT_ID, CLIENT_ID).with_lifetime(Duration::minutes(11)),
        ClientJwtClaims::new(CLIENT_ID, CLIENT_ID).with_lifetime(Duration::days(180)),
    ] {
        let config = private_key_jwt_config(claims.clone());
        assert!(
            matches!(config.validate(), Err(AuthError::InvalidConfiguration(_))),
            "{claims:?} was accepted for private_key_jwt"
        );
    }
    private_key_jwt_config(
        ClientJwtClaims::new(CLIENT_ID, CLIENT_ID).with_lifetime(Duration::minutes(10)),
    )
    .validate()
    .unwrap();

    // A signed client secret (Sign in with Apple) keeps its own issuer and
    // the longer documented lifetime.
    let mut apple = generic_config(DISCOVERY_URL);
    apple.client_jwt = Some(
        rsa_signer(
            ClientJwtClaims::new("TEAM123456", CLIENT_ID)
                .with_audience("https://appleid.apple.com")
                .with_lifetime(Duration::days(180)),
        )
        .unwrap(),
    );
    apple.validate().unwrap();
}
