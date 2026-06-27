//! Commonly used `agql-auth` exports.
//!
//! Import this module when you want the primary service, models, stores,
//! guards, OIDC helpers, and session types in one place.

pub use crate::config::{
    AuthConfig, ClientMetadata, JwtSigningConfig, MicrosoftEntraConfig, MicrosoftEntraTenant,
    OidcProviderConfig, OidcProviderKind,
};
pub use crate::errors::AuthError;
pub use crate::graphql::{auth_user_from_ctx, auth_user_from_ctx_opt};
pub use crate::guards::{
    RequireAllRoles, RequireAllScopes, RequireAnyRole, RequireAnyScope, RequireAuth, RequireScope,
};
pub use crate::models::{
    AuthPayload, AuthUser, ExternalIdentity, IssuedLoginChallenge, LoginChallengeOptions,
    MicrosoftEntraClaims, OAuthLoginState, OidcAuthorizationRequest, OidcCallbackInput,
    OidcLoginResult, OidcTokenResponse, PasswordResetToken, RefreshTokenRevocationReason,
    StoredLoginChallenge, StoredRefreshToken, StoredUser, TotpOptions, TotpProvisioning,
    TotpSecret, ValidatedOidcClaims, VerifiedLoginChallenge, VerifiedPasswordResetToken,
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
    ExternalIdentityStore, LoginChallengeStore, OAuthStateStore, OAuthTokenStore,
    PasswordResetTokenStore, RefreshTokenStore, UserStore,
};
