//! Commonly used `agql-auth` exports.
//!
//! Import this module when you want the primary service, models, stores,
//! guards, OIDC helpers, and session types in one place.

pub use crate::api_tokens::{ApiTokenService, DEFAULT_API_TOKEN_PREFIX};
pub use crate::assurance::{
    AssuranceDenial, AssuranceDenialCode, AssuranceEvaluation, AssuranceEvaluationState,
    AssuranceInputError, AssuranceMatchMode, AssurancePolicyId, AssurancePolicyIdError,
    AssurancePolicySet, AssuranceRequirement, AuthenticatedAt, MAX_ASSURANCE_CONTEXT_LENGTH,
    MAX_ASSURANCE_METHOD_LENGTH, MAX_ASSURANCE_METHODS, MAX_ASSURANCE_POLICY_ID_LENGTH,
    MfaAcceptance, RecentMfaPolicy, RefreshableTokenMetadata, SatisfiedUntil, ServerEvaluationTime,
    SessionAssurance, SessionAssuranceStatus, StepUpAuthentication,
};
pub use crate::channel::ChannelIdentity;
pub use crate::claims::{
    AccessTokenMetadata, ActorIdentity, ClaimRequirements, ConfirmationClaims,
};
pub use crate::clock::{Clock, FixedClock, SystemClock};
pub use crate::combined::{AccessTokenAuth, CombinedAuth};
pub use crate::config::{
    AccessTokenScopeClaimFormat, AuthConfig, AuthRateLimitConfig, AuthRateLimitPolicy,
    ClientMetadata, JwtSigningConfig, LegacyScopeClaims, MicrosoftEntraConfig,
    MicrosoftEntraTenant, OidcProviderConfig, OidcProviderKind,
};
pub use crate::decision::{
    AuthorizationDecision, AuthorizationDecisionHook, AuthorizationInvocation,
    AuthorizationOutcome, AuthorizationReasonCode, LinkedAuthorizationDecision,
};
pub use crate::errors::AuthError;
pub use crate::grant::{AccessTokenOnlyGrant, AccessTokenOnlyRequest};
pub use crate::graphql::{
    GraphqlRefreshCookieConfig, GraphqlRefreshCookieDirective, GraphqlTopLevelField,
    auth_runtime_from_ctx_opt, auth_user_from_ctx, auth_user_from_ctx_opt,
    channel_identity_from_ctx, channel_identity_from_ctx_opt, graphql_refresh_cookie_directive,
    principal_from_ctx, principal_from_ctx_opt, scope_matcher_from_ctx,
};
pub use crate::guards::{
    RequireAllPrincipalScopes, RequireAllRoles, RequireAllScopes, RequireAnyPrincipalScope,
    RequireAnyRole, RequireAnyScope, RequireAuth, RequireChannelScheme, RequirePrincipal,
    RequirePrincipalScope, RequireScope,
};
pub use crate::keys::{
    AccessTokenKeyResolver, KeyRefreshPolicy, RotatingJwksKeySet, StaleKeyPolicy, StaticJwksKeySet,
    StaticRs256Key,
};
pub use crate::models::{
    ApiTokenIssueRequest, ApiTokenPrincipal, ApiTokenPrincipalKind, ApiTokenRevocationReason,
    AuthPayload, AuthPrincipal, AuthRateLimitBucket, AuthRateLimitFlow, AuthRateLimitKey,
    AuthRateLimitSnapshot, AuthRateLimitState, AuthUser, ExternalIdentity, IssuedApiToken,
    IssuedLoginChallenge, IssuedPurposeToken, LoginChallengeOptions, MicrosoftEntraClaims,
    OAuthLoginState, OidcAuthorizationRequest, OidcCallbackInput, OidcLoginResult,
    OidcTokenResponse, PasswordResetToken, PurposeTokenIssueRequest, PurposeTokenValidation,
    RefreshTokenRevocationReason, StoredApiToken, StoredLoginChallenge, StoredRefreshToken,
    StoredUser, TotpOptions, TotpProvisioning, TotpSecret, ValidatedOidcClaims,
    VerifiedLoginChallenge, VerifiedPasswordResetToken, VerifiedPurposeToken,
};
pub use crate::oidc::{
    ClaimsMapper, ExternalUserProvisioner, MappedClaims, MicrosoftClaimsMapper, NoopClaimsMapper,
    OidcCallbackOutcome, OidcDiscoveryDocument, OidcHttpClient, OidcProvider, PkcePair,
    ProvisionedExternalUser, generate_oauth_state, generate_oidc_nonce, generate_pkce_pair,
    hash_oauth_state, pkce_s256_challenge, stable_external_subject,
};
pub use crate::oidc_authorization::{
    MAX_OIDC_AUTHORIZATION_TOTAL_VALUE_LENGTH, MAX_OIDC_AUTHORIZATION_VALUE_LENGTH,
    MAX_OIDC_AUTHORIZATION_VALUES, MAX_OIDC_CLAIMS_REQUEST_LENGTH, MAX_OIDC_MAX_AGE_SECONDS,
    OidcAuthorizationOptions, OidcAuthorizationOutcome, OidcAuthorizationPolicy,
    OidcIdTokenClaimRequest, OidcPrompt,
};
pub use crate::principal_reference::{
    CurrentPrincipalResolver, PrincipalReference, PrincipalReferenceKind, ResolvedPrincipal,
};
pub use crate::purpose_grant::{PurposeBoundGrantReference, PurposeGrantStatus};
pub use crate::scope_match::{
    AuthRuntime, ExactScopeMatch, HierarchicalScopeMatch, HierarchicalScopeOptions, ScopeMatch,
    ScopeMatcher,
};
pub use crate::scopes::{has_all_scopes, has_any_scope, has_scope};
pub use crate::service::AuthService;
pub use crate::session::{ActiveScope, AuthMethod, MfaFactor, MfaState, SessionContext};
pub use crate::stores::{
    ApiTokenStore, AuthRateLimitStore, ExternalIdentityStore, LoginChallengeStore,
    MemoryAuthRateLimitStore, OAuthStateStore, OAuthTokenStore, PasswordResetTokenStore,
    RefreshTokenStore, TotpReplayStore, UserStore,
};
pub use crate::token_decode::{
    BearerParseMode, MAX_ACCESS_TOKEN_SCOPE_CLAIM_LENGTH, MAX_ACCESS_TOKEN_SCOPE_LENGTH,
    MAX_ACCESS_TOKEN_SCOPES, PurposePolicy,
};
pub use crate::token_status::{
    AlwaysActiveTokenStatus, ReauthorizationPolicy, StatusCheckFailureMode, TokenStatus,
    TokenStatusChecker, TokenStatusRequest,
};
pub use crate::validator::{AccessTokenValidator, AccessTokenValidatorBuilder};
