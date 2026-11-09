//! Callback binding for OIDC and OAuth 2.0: browser binding against login
//! CSRF, the RFC 9207 `iss` response parameter, OAuth 2.0 session issuance,
//! client-assertion header options and the injected clock for ID tokens.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde_json::{Value as JsonValue, json};
use time::{Duration, OffsetDateTime};

use super::oidc::{
    CLIENT_ID, DISCOVERY_URL, ISSUER, JWKS_URI, MemoryExternalIdentityStore, MemoryOAuthStateStore,
    REDIRECT_URI, RSA_PRIVATE_KEY, TENANT_ID, TOKEN_ENDPOINT, callback_with_code,
    discovery_document, jwks_document, signed_id_token, valid_claims,
};
use super::provider_http::{RecordingHttpClient, bearer_token_response};
use super::{MemoryRefreshTokenStore, MemoryUserStore, metadata, stored_user, test_auth_service};
use crate::prelude::*;

const RSA_N: &str = "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ";
const GITHUB_USER: &str = "https://api.github.com/user";
const GITHUB_EMAILS: &str = "https://api.github.com/user/emails";
const GITHUB_REDIRECT: &str = "https://app.example.test/auth/github/callback";
const OAUTH2_ISSUER: &str = "https://github.example.test";
const ORGANIZATIONS_DISCOVERY_URL: &str =
    "https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration";
const ORGANIZATIONS_JWKS_URI: &str =
    "https://login.microsoftonline.com/organizations/discovery/v2.0/keys";
const OTHER_TENANT_ISSUER: &str =
    "https://login.microsoftonline.com/33333333-3333-3333-3333-333333333333/v2.0";

fn oidc_client() -> RecordingHttpClient {
    let client = RecordingHttpClient::new(true);
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

fn generic_provider(client: &RecordingHttpClient, config: OidcProviderConfig) -> OidcProvider {
    OidcProvider::new(config, Arc::new(client.clone())).unwrap()
}

fn generic_config() -> OidcProviderConfig {
    OidcProviderConfig::new("generic", DISCOVERY_URL, CLIENT_ID, REDIRECT_URI)
}

async fn start(
    provider: &OidcProvider,
    client: &RecordingHttpClient,
    store: &MemoryOAuthStateStore,
) -> OidcAuthorizationRequest {
    let request = provider.create_authorization_request(store).await.unwrap();
    client.set_post(Ok(token_response(signed_id_token(
        valid_claims(&request.nonce),
        "rsa01",
    ))));
    request
}

fn stored_state(store: &MemoryOAuthStateStore, provider: &str, state: &str) -> OAuthLoginState {
    store
        .states
        .lock()
        .unwrap()
        .get(&(provider.to_string(), hash_oauth_state(state)))
        .unwrap()
        .clone()
}

#[tokio::test]
async fn oidc_callback_requires_the_initiating_browser_binding() {
    let client = oidc_client();
    let provider = generic_provider(&client, generic_config());
    let store = MemoryOAuthStateStore::default();

    let request = start(&provider, &client, &store).await;
    let binding = request.browser_binding.clone().unwrap();
    assert!(binding.len() >= 43);
    let stored = stored_state(&store, "generic", &request.state);
    assert_eq!(
        stored.browser_binding_hash.as_deref(),
        Some(hash_oauth_state(&binding).as_str())
    );
    assert!(!format!("{request:?}{stored:?}").contains(&binding));
    // The hash survives a store round trip.
    let persisted: OAuthLoginState =
        serde_json::from_value(serde_json::to_value(&stored).unwrap()).unwrap();
    assert_eq!(persisted.browser_binding_hash, stored.browser_binding_hash);

    // A forged callback from another browser carries no binding cookie.
    let forged = provider
        .handle_callback(
            &store,
            OidcCallbackInput::code_and_state("attacker-code", &request.state),
        )
        .await
        .unwrap_err();
    assert!(matches!(forged, AuthError::InvalidOAuthState));
    assert_eq!(forged.public_code(), "INVALID_OAUTH_STATE");
    // The state is burned: the right browser cannot complete it afterwards.
    let after = provider
        .handle_callback(&store, callback_with_code(&request, "auth-code"))
        .await
        .unwrap_err();
    assert!(matches!(after, AuthError::InvalidOAuthState));

    let request = start(&provider, &client, &store).await;
    let wrong = provider
        .handle_callback(
            &store,
            OidcCallbackInput::code_and_state("auth-code", &request.state)
                .with_browser_binding(format!("{binding}x")),
        )
        .await
        .unwrap_err();
    assert!(matches!(wrong, AuthError::InvalidOAuthState));
    assert!(client.posts().is_empty(), "no code was exchanged");

    let request = start(&provider, &client, &store).await;
    provider
        .handle_callback(&store, callback_with_code(&request, "auth-code"))
        .await
        .unwrap();
    assert_eq!(client.posts().len(), 1);
}

#[tokio::test]
async fn browser_binding_opt_out_is_explicit_and_legacy_states_fail_closed() {
    let client = oidc_client();
    let store = MemoryOAuthStateStore::default();
    let mut config = generic_config();
    config.browser_binding = OAuthBrowserBinding::NotRequiredHostBindsState;
    let opted_out = generic_provider(&client, config);
    let request = start(&opted_out, &client, &store).await;
    assert_eq!(request.browser_binding, None);
    assert_eq!(
        stored_state(&store, "generic", &request.state).browser_binding_hash,
        None
    );
    opted_out
        .handle_callback(
            &store,
            OidcCallbackInput::code_and_state("auth-code", &request.state),
        )
        .await
        .unwrap();

    // A state without a binding hash (written before 0.27.0, or by the
    // opted-out configuration) is refused once binding is required.
    let required = generic_provider(&client, generic_config());
    let request = start(&opted_out, &client, &store).await;
    let refused = required
        .handle_callback(
            &store,
            OidcCallbackInput::code_and_state("auth-code", &request.state)
                .with_browser_binding("anything"),
        )
        .await
        .unwrap_err();
    assert!(matches!(refused, AuthError::InvalidOAuthState));

    // A bound state still requires its value after opting out.
    let request = start(&required, &client, &store).await;
    let refused = opted_out
        .handle_callback(
            &store,
            OidcCallbackInput::code_and_state("auth-code", &request.state),
        )
        .await
        .unwrap_err();
    assert!(matches!(refused, AuthError::InvalidOAuthState));
}

fn github_client() -> RecordingHttpClient {
    let client = RecordingHttpClient::new(true);
    client.set_post(Ok(bearer_token_response("gho_token")));
    client.set_get(GITHUB_USER, Ok(json!({"id": 583231, "name": "Octocat"})));
    client.set_get(GITHUB_EMAILS, Ok(json!([])));
    client
}

fn github(client: &RecordingHttpClient, config: OAuth2ProviderConfig) -> OAuth2Provider {
    OAuth2Provider::new(config, Arc::new(client.clone())).unwrap()
}

fn github_config() -> OAuth2ProviderConfig {
    OAuth2ProviderConfig::github("client", "secret", GITHUB_REDIRECT)
}

fn oauth2_callback(request: &OAuth2AuthorizationRequest) -> OidcCallbackInput {
    OidcCallbackInput::code_and_state("auth-code", &request.state)
        .with_browser_binding(request.browser_binding.clone().unwrap())
}

#[tokio::test]
async fn oauth2_callback_requires_the_initiating_browser_binding() {
    let client = github_client();
    let provider = github(&client, github_config());
    let store = MemoryOAuthStateStore::default();

    let request = provider.create_authorization_request(&store).await.unwrap();
    let forged = provider
        .handle_callback(
            &store,
            OidcCallbackInput::code_and_state("attacker-code", &request.state),
        )
        .await
        .unwrap_err();
    assert!(matches!(forged, AuthError::InvalidOAuthState));
    let after = provider
        .handle_callback(&store, oauth2_callback(&request))
        .await
        .unwrap_err();
    assert!(matches!(after, AuthError::InvalidOAuthState));
    assert!(client.posts().is_empty());

    let request = provider.create_authorization_request(&store).await.unwrap();
    provider
        .handle_callback(&store, oauth2_callback(&request))
        .await
        .unwrap();

    let mut config = github_config();
    config.browser_binding = OAuthBrowserBinding::NotRequiredHostBindsState;
    let opted_out = github(&client, config);
    let request = opted_out
        .create_authorization_request(&store)
        .await
        .unwrap();
    assert_eq!(request.browser_binding, None);
    opted_out
        .handle_callback(
            &store,
            OidcCallbackInput::code_and_state("auth-code", &request.state),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn oidc_authorization_response_iss_is_checked_before_code_exchange() {
    let client = oidc_client();
    let provider = generic_provider(&client, generic_config());
    let store = MemoryOAuthStateStore::default();

    let request = start(&provider, &client, &store).await;
    let mixed_up = provider
        .handle_callback(
            &store,
            callback_with_code(&request, "auth-code").with_issuer("https://attacker.example.test"),
        )
        .await
        .unwrap_err();
    assert!(matches!(mixed_up, AuthError::OidcCallback(_)));
    assert!(client.posts().is_empty(), "the code never left");

    let request = start(&provider, &client, &store).await;
    provider
        .handle_callback(
            &store,
            callback_with_code(&request, "auth-code").with_issuer(ISSUER),
        )
        .await
        .unwrap();

    // A provider advertising RFC 9207 support must return iss.
    let advertising = oidc_client();
    let mut document = discovery_document();
    document["authorization_response_iss_parameter_supported"] = json!(true);
    advertising.set_get(DISCOVERY_URL, Ok(document));
    let provider = generic_provider(&advertising, generic_config());
    let request = start(&provider, &advertising, &store).await;
    let missing = provider
        .handle_callback(&store, callback_with_code(&request, "auth-code"))
        .await
        .unwrap_err();
    assert!(matches!(missing, AuthError::OidcCallback(_)));
    let request = start(&provider, &advertising, &store).await;
    provider
        .handle_callback(
            &store,
            callback_with_code(&request, "auth-code").with_issuer(ISSUER),
        )
        .await
        .unwrap();
    assert_eq!(advertising.posts().len(), 1);
}

#[tokio::test]
async fn entra_multi_tenant_response_iss_must_match_the_id_token_tenant() {
    let client = RecordingHttpClient::new(true);
    client.set_get(
        ORGANIZATIONS_DISCOVERY_URL,
        Ok(json!({
            "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0",
            "authorization_endpoint": "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize",
            "token_endpoint": "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
            "jwks_uri": ORGANIZATIONS_JWKS_URI
        })),
    );
    client.set_get(ORGANIZATIONS_JWKS_URI, Ok(jwks_document("rsa01")));
    let provider = generic_provider(
        &client,
        MicrosoftEntraConfig::organizations(CLIENT_ID, REDIRECT_URI)
            .into_oidc_provider_config()
            .unwrap(),
    );
    let store = MemoryOAuthStateStore::default();

    for (iss, accepted) in [
        (ISSUER, true),
        (OTHER_TENANT_ISSUER, false),
        ("https://login.microsoftonline.com/a/b/v2.0", false),
        ("https://login.microsoftonline.com//v2.0", false),
    ] {
        let request = start(&provider, &client, &store).await;
        let result = provider
            .handle_callback(
                &store,
                callback_with_code(&request, "auth-code").with_issuer(iss),
            )
            .await;
        assert_eq!(result.is_ok(), accepted, "{iss}");
        if let Err(error) = result {
            assert!(matches!(error, AuthError::OidcCallback(_)), "{iss}");
        }
    }
}

#[tokio::test]
async fn oauth2_authorization_response_iss_requires_a_configured_issuer() {
    let store = MemoryOAuthStateStore::default();
    let client = github_client();
    let provider = github(&client, github_config());
    let request = provider.create_authorization_request(&store).await.unwrap();
    let unknown = provider
        .handle_callback(&store, oauth2_callback(&request).with_issuer(OAUTH2_ISSUER))
        .await
        .unwrap_err();
    assert!(matches!(unknown, AuthError::OAuthCallback(_)));
    assert!(client.posts().is_empty());

    let mut config = github_config();
    config.issuer = Some(OAUTH2_ISSUER.to_string());
    config.require_authorization_response_iss = true;
    let provider = github(&client, config);
    for (iss, accepted) in [
        (None, false),
        (Some("https://attacker.example.test"), false),
        (Some(OAUTH2_ISSUER), true),
    ] {
        let request = provider.create_authorization_request(&store).await.unwrap();
        let mut input = oauth2_callback(&request);
        input.iss = iss.map(str::to_string);
        let result = provider.handle_callback(&store, input).await;
        assert_eq!(result.is_ok(), accepted, "{iss:?}");
    }
    assert_eq!(client.posts().len(), 1);

    let mut config = github_config();
    config.require_authorization_response_iss = true;
    assert!(matches!(
        config.validate(),
        Err(AuthError::InvalidConfiguration(_))
    ));
    let mut config = github_config();
    config.issuer = Some("http://github.example.test".to_string());
    assert!(matches!(
        config.validate(),
        Err(AuthError::InvalidConfiguration(_))
    ));
}

struct GithubProvisioner {
    user_id: String,
}

#[async_trait]
impl OAuth2UserProvisioner for GithubProvisioner {
    async fn resolve_oauth2_user(
        &self,
        profile: &OAuth2UserProfile,
        existing_identity: Option<&ExternalIdentity>,
    ) -> crate::AuthResult<ProvisionedExternalUser> {
        assert_eq!(profile.subject, "583231");
        let user_id = existing_identity
            .map_or_else(|| self.user_id.clone(), |identity| identity.user_id.clone());
        Ok(ProvisionedExternalUser::new(
            user_id,
            vec!["Developer".to_string()],
            vec!["repos.read".to_string()],
        ))
    }
}

struct ImpostorProvisioner;

#[async_trait]
impl OAuth2UserProvisioner for ImpostorProvisioner {
    async fn resolve_oauth2_user(
        &self,
        _profile: &OAuth2UserProfile,
        _existing_identity: Option<&ExternalIdentity>,
    ) -> crate::AuthResult<ProvisionedExternalUser> {
        Ok(ProvisionedExternalUser::new("other-user", vec![], vec![]))
    }
}

#[tokio::test]
async fn oauth2_login_with_callback_enforces_local_account_state_and_issues_a_session() {
    let users = MemoryUserStore::default();
    let auth = test_auth_service(users.clone(), MemoryRefreshTokenStore::default());
    let mut user = stored_user(&auth, "local-user", "octocat@example.test", "password");
    user.disabled = true;
    users.insert(user.clone());
    let client = github_client();
    let provider = github(&client, github_config());
    let store = MemoryOAuthStateStore::default();
    let identities = MemoryExternalIdentityStore::default();
    let provisioner = GithubProvisioner {
        user_id: "local-user".to_string(),
    };

    let request = provider.create_authorization_request(&store).await.unwrap();
    let disabled = provider
        .login_with_callback(
            &auth,
            &store,
            &identities,
            &provisioner,
            oauth2_callback(&request),
            metadata(),
        )
        .await
        .unwrap_err();
    assert!(matches!(disabled, AuthError::UserDisabled));
    assert!(identities.identities.lock().unwrap().is_empty());

    let missing_provisioner = GithubProvisioner {
        user_id: "missing-user".to_string(),
    };
    let request = provider.create_authorization_request(&store).await.unwrap();
    let missing = provider
        .login_with_callback(
            &auth,
            &store,
            &identities,
            &missing_provisioner,
            oauth2_callback(&request),
            metadata(),
        )
        .await
        .unwrap_err();
    assert!(matches!(missing, AuthError::ExternalLoginRejected(_)));
    assert!(identities.identities.lock().unwrap().is_empty());

    user.disabled = false;
    users.insert(user);
    let request = provider.create_authorization_request(&store).await.unwrap();
    let result = provider
        .login_with_callback(
            &auth,
            &store,
            &identities,
            &provisioner,
            oauth2_callback(&request),
            metadata(),
        )
        .await
        .unwrap();
    assert_eq!(result.auth.user.user_id, "local-user");
    assert_eq!(result.auth.user.session.auth_method, AuthMethod::OAuth2);
    assert_eq!(result.auth.user.roles, vec!["Developer".to_string()]);
    assert_eq!(result.auth.user.scopes, vec!["repos.read".to_string()]);
    assert_eq!(result.external_identity.external_subject, "583231");
    assert_eq!(result.external_identity.provider_name, "github");
    assert_eq!(result.profile.name.as_deref(), Some("Octocat"));
    assert!(!format!("{result:?}").contains("gho_token"));
    assert_eq!(
        auth.authenticate_access_token(&result.auth.access_token)
            .unwrap()
            .session
            .auth_method,
        AuthMethod::OAuth2
    );
    assert!(
        identities
            .identities
            .lock()
            .unwrap()
            .contains_key(&("github".to_string(), "583231".to_string()))
    );

    let request = provider.create_authorization_request(&store).await.unwrap();
    let hijack = provider
        .login_with_callback(
            &auth,
            &store,
            &identities,
            &ImpostorProvisioner,
            oauth2_callback(&request),
            metadata(),
        )
        .await
        .unwrap_err();
    assert!(matches!(hijack, AuthError::ExternalLoginRejected(_)));
}

fn rsa_signer(claims: ClientJwtClaims) -> crate::AuthResult<ClientJwtSigner> {
    ClientJwtSigner::from_pem(
        ClientJwtAlgorithm::RS256,
        RSA_PRIVATE_KEY.as_bytes(),
        claims,
    )
}

#[tokio::test]
async fn client_assertion_carries_optional_x5t_s256_and_nbf() {
    let thumbprint = URL_SAFE_NO_PAD.encode([7u8; 32]);
    let client = oidc_client();
    let mut config = MicrosoftEntraConfig::single_tenant(TENANT_ID, CLIENT_ID, REDIRECT_URI)
        .into_oidc_provider_config()
        .unwrap();
    config.token_endpoint_auth_method = TokenEndpointAuthMethod::PrivateKeyJwt;
    config.client_jwt = Some(
        rsa_signer(
            ClientJwtClaims::new(CLIENT_ID, CLIENT_ID)
                .with_x509_sha256_thumbprint(thumbprint.clone())
                .with_not_before(),
        )
        .unwrap(),
    );
    let provider = generic_provider(&client, config);
    let store = MemoryOAuthStateStore::default();
    let request = start(&provider, &client, &store).await;
    provider
        .handle_callback(&store, callback_with_code(&request, "auth-code"))
        .await
        .unwrap();

    let assertion = client.posts()[0]
        .form_value("client_assertion")
        .unwrap()
        .to_string();
    let header = decode_header(&assertion).unwrap();
    assert_eq!(header.x5t_s256.as_deref(), Some(thumbprint.as_str()));
    // Microsoft Entra documents the token endpoint as the assertion audience.
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[TOKEN_ENDPOINT]);
    let claims = decode::<JsonValue>(
        &assertion,
        &DecodingKey::from_rsa_components(RSA_N, "AQAB").unwrap(),
        &validation,
    )
    .unwrap()
    .claims;
    assert_eq!(claims["nbf"], claims["iat"]);

    for invalid in ["not-base64!", "AAAA", &URL_SAFE_NO_PAD.encode([7u8; 20])] {
        assert!(matches!(
            rsa_signer(
                ClientJwtClaims::new(CLIENT_ID, CLIENT_ID).with_x509_sha256_thumbprint(invalid)
            ),
            Err(AuthError::InvalidConfiguration(_))
        ));
    }
}

#[tokio::test]
async fn id_token_time_checks_use_the_provider_clock() {
    let client = oidc_client();
    let real_now = OffsetDateTime::now_utc();
    let clock = FixedClock::new(real_now);
    let mut config = generic_config();
    config.state_ttl = Duration::minutes(30);
    let provider =
        OidcProvider::new_with_clock(config, Arc::new(client.clone()), Arc::new(clock.clone()))
            .unwrap();
    let store = MemoryOAuthStateStore::default();

    // `valid_claims` expires ten minutes after the real time and has a
    // one-minute clock skew; a provider clock past that refuses it even though
    // the system clock would accept it.
    let request = provider.create_authorization_request(&store).await.unwrap();
    let claims = valid_claims(&request.nonce);
    clock.set(real_now + Duration::minutes(12));
    client.set_post(Ok(token_response(signed_id_token(claims, "rsa01"))));
    let expired = provider
        .handle_callback(&store, callback_with_code(&request, "auth-code"))
        .await
        .unwrap_err();
    assert!(matches!(expired, AuthError::OidcTokenValidation(_)));

    // A provider clock before `nbf` (minus skew) refuses it too.
    clock.set(real_now);
    let request = provider.create_authorization_request(&store).await.unwrap();
    let mut claims = valid_claims(&request.nonce);
    claims["iat"] = json!((real_now - Duration::minutes(30)).unix_timestamp());
    claims["nbf"] = json!((real_now + Duration::minutes(5)).unix_timestamp());
    client.set_post(Ok(token_response(signed_id_token(claims, "rsa01"))));
    let early = provider
        .handle_callback(&store, callback_with_code(&request, "auth-code"))
        .await
        .unwrap_err();
    assert!(matches!(early, AuthError::OidcTokenValidation(_)));

    // A token the system clock considers expired is accepted at the provider
    // clock's earlier time.
    clock.set(real_now - Duration::hours(2));
    let request = provider.create_authorization_request(&store).await.unwrap();
    let mut claims = valid_claims(&request.nonce);
    claims["iat"] = json!((real_now - Duration::hours(2)).unix_timestamp());
    claims["nbf"] = json!((real_now - Duration::hours(2)).unix_timestamp());
    claims["exp"] = json!((real_now - Duration::hours(1)).unix_timestamp());
    client.set_post(Ok(token_response(signed_id_token(claims, "rsa01"))));
    provider
        .handle_callback(&store, callback_with_code(&request, "auth-code"))
        .await
        .unwrap();
}
