//! Database-agnostic authentication primitives and `async-graphql` helpers.
//!
//! `agql-auth` gives host applications reusable authentication building blocks
//! without taking over the host's database, HTTP framework, cookie policy, user
//! provisioning, or business authorization model.
//!
//! ## Core Pieces
//!
//! - [`AuthService`] issues and validates local sessions.
//! - [`AuthConfig`] configures issuer, audience, TTLs, and JWT signing mode.
//! - [`UserStore`] and [`RefreshTokenStore`] let the host provide persistence.
//! - [`AuthUser`] is injected into `async-graphql` request data after
//!   authentication.
//! - [`RequireAuth`], [`RequireAnyRole`], [`RequireScope`], and related guards
//!   protect resolvers.
//!
//! ## Local Sessions
//!
//! Access tokens are short-lived JWTs containing the local user ID, session ID,
//! roles, scopes, and [`SessionContext`]. Refresh tokens are opaque, hashed
//! before storage, and rotated on refresh. A replayed refresh token revokes the
//! token family through the host's [`RefreshTokenStore`].
//!
//! ## JWT Signing And JWKS
//!
//! [`AuthConfig::new`] preserves the legacy HS256 behavior. New deployments that
//! need routers or other services to validate local `agql-auth` tokens should
//! use [`AuthConfig::with_rs256_pem`]. RS256 tokens include the configured
//! `kid`, validate locally with public key material, and can be exposed through
//! [`AuthService::jwks`].
//!
//! ## OIDC And Microsoft Entra ID
//!
//! [`OidcProvider`] owns OIDC discovery, authorization URL generation, token
//! exchange, JWKS caching, ID-token validation, state and nonce validation, and
//! the handoff into local [`AuthService`] session issuance.
//!
//! Microsoft Entra ID setup starts with [`MicrosoftEntraConfig`]. Host
//! applications provide an [`OAuthStateStore`] with atomic one-time state
//! consumption, an [`ExternalIdentityStore`] for stable provider links, an
//! [`ExternalUserProvisioner`] for account creation/linking/rejection, and an
//! optional [`ClaimsMapper`] for local roles and scopes.
//!
//! Microsoft access tokens are not used as local authorization tokens. After a
//! successful OIDC callback, `agql-auth` returns an [`OidcLoginResult`] whose
//! `auth` field is a normal local [`AuthPayload`].
//!
//! ## More Documentation
//!
//! The repository README links focused guides for storage traits, authorization,
//! JWT signing and JWKS, Microsoft Entra OIDC, recovery flows, and MFA
//! primitives.

mod config;
mod errors;
mod graphql;
mod guards;
mod models;
mod oidc;
pub mod prelude;
mod scopes;
mod service;
mod session;
mod stores;
mod util;

#[cfg(test)]
mod tests;

pub use config::{
    AuthConfig, ClientMetadata, JwtSigningConfig, MicrosoftEntraConfig, MicrosoftEntraTenant,
    OidcProviderConfig, OidcProviderKind,
};
pub use errors::AuthError;
pub use graphql::{auth_user_from_ctx, auth_user_from_ctx_opt};
pub use guards::{
    RequireAllRoles, RequireAllScopes, RequireAnyRole, RequireAnyScope, RequireAuth, RequireScope,
};
pub use models::{
    AuthPayload, AuthUser, ExternalIdentity, IssuedLoginChallenge, LoginChallengeOptions,
    MicrosoftEntraClaims, OAuthLoginState, OidcAuthorizationRequest, OidcCallbackInput,
    OidcLoginResult, OidcTokenResponse, PasswordResetToken, RefreshTokenRevocationReason,
    StoredLoginChallenge, StoredRefreshToken, StoredUser, TotpOptions, TotpProvisioning,
    TotpSecret, ValidatedOidcClaims, VerifiedLoginChallenge, VerifiedPasswordResetToken,
};
pub use oidc::{
    ClaimsMapper, ExternalUserProvisioner, MappedClaims, MicrosoftClaimsMapper, NoopClaimsMapper,
    OidcCallbackOutcome, OidcDiscoveryDocument, OidcHttpClient, OidcProvider, PkcePair,
    ProvisionedExternalUser, generate_oauth_state, generate_oidc_nonce, generate_pkce_pair,
    hash_oauth_state, pkce_s256_challenge, stable_external_subject,
};
pub use scopes::{has_all_scopes, has_any_scope, has_scope};
pub use service::AuthService;
pub use session::{ActiveScope, AuthMethod, MfaMethod, MfaState, SessionContext};
pub use stores::{
    ExternalIdentityStore, LoginChallengeStore, OAuthStateStore, OAuthTokenStore,
    PasswordResetTokenStore, RefreshTokenStore, UserStore,
};

pub type AuthResult<T> = Result<T, AuthError>;
