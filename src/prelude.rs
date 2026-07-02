//! Commonly used `agql-auth` exports.
//!
//! Import this module when you want the primary service, models, stores,
//! guards, OIDC helpers, and session types in one place.

pub use crate::api_tokens::{ApiTokenService, DEFAULT_API_TOKEN_PREFIX};
pub use crate::config::{
    AuthConfig, AuthRateLimitConfig, AuthRateLimitPolicy, ClientMetadata, JwtSigningConfig,
    MicrosoftEntraConfig, MicrosoftEntraTenant, OidcProviderConfig, OidcProviderKind,
};
pub use crate::errors::AuthError;
pub use crate::graphql::{
    auth_user_from_ctx, auth_user_from_ctx_opt, principal_from_ctx, principal_from_ctx_opt,
};
pub use crate::guards::{
    RequireAllPrincipalScopes, RequireAllRoles, RequireAllScopes, RequireAnyPrincipalScope,
    RequireAnyRole, RequireAnyScope, RequireAuth, RequirePrincipal, RequirePrincipalScope,
    RequireScope,
};
pub use crate::models::{
    ApiTokenIssueRequest, ApiTokenPrincipal, ApiTokenPrincipalKind, ApiTokenRevocationReason,
    AuthPayload, AuthPrincipal, AuthRateLimitBucket, AuthRateLimitFlow, AuthRateLimitKey,
    AuthRateLimitState, AuthUser, ExternalIdentity, IssuedApiToken, IssuedLoginChallenge,
    LoginChallengeOptions, MicrosoftEntraClaims, OAuthLoginState, OidcAuthorizationRequest,
    OidcCallbackInput, OidcLoginResult, OidcTokenResponse, PasswordResetToken,
    RefreshTokenRevocationReason, StoredApiToken, StoredLoginChallenge, StoredRefreshToken,
    StoredUser, TotpOptions, TotpProvisioning, TotpSecret, ValidatedOidcClaims,
    VerifiedLoginChallenge, VerifiedPasswordResetToken,
};
pub use crate::oidc::{
    ClaimsMapper, ExternalUserProvisioner, MappedClaims, MicrosoftClaimsMapper, NoopClaimsMapper,
    OidcCallbackOutcome, OidcDiscoveryDocument, OidcHttpClient, OidcProvider, PkcePair,
    ProvisionedExternalUser, generate_oauth_state, generate_oidc_nonce, generate_pkce_pair,
    hash_oauth_state, pkce_s256_challenge, stable_external_subject,
};
pub use crate::scopes::{has_all_scopes, has_any_scope, has_scope};
pub use crate::service::AuthService;
pub use crate::session::{ActiveScope, AuthMethod, MfaMethod, MfaState, SessionContext};
pub use crate::stores::{
    ApiTokenStore, AuthRateLimitStore, ExternalIdentityStore, LoginChallengeStore,
    MemoryAuthRateLimitStore, OAuthStateStore, OAuthTokenStore, PasswordResetTokenStore,
    RefreshTokenStore, TotpReplayStore, UserStore,
};
