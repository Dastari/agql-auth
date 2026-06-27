use serde::{Deserialize, Serialize};

/// Local method used to establish an `agql-auth` session.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthMethod {
    /// Username/password login.
    #[default]
    Password,
    /// Email-code login or verification flow.
    EmailCode,
    /// SMS-code login or verification flow.
    SmsCode,
    /// TOTP step-up flow.
    TotpStepUp,
    /// Host-issued service token flow.
    ServiceToken,
    /// Generic OIDC login flow.
    Oidc,
    /// Microsoft Entra ID OIDC login flow.
    MicrosoftOidc,
}

/// MFA state attached to the local session context.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MfaState {
    /// Whether the session has satisfied the host's MFA policy.
    pub satisfied: bool,
    /// MFA methods satisfied by the session.
    pub methods: Vec<MfaMethod>,
}

/// Supported MFA methods recorded in local session context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MfaMethod {
    /// Time-based one-time password.
    Totp,
}

/// Optional active business scope for a session.
///
/// This is application context, not an authorization decision by itself.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveScope {
    /// Active tenant ID.
    pub tenant_id: Option<String>,
    /// Active organization ID.
    pub organization_id: Option<String>,
    /// Active catalog ID.
    pub catalog_id: Option<String>,
}

/// Typed context embedded in the local access-token `ctx` claim.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionContext {
    /// Method used to establish the session.
    #[serde(default)]
    pub auth_method: AuthMethod,
    /// MFA state associated with the session.
    #[serde(default)]
    pub mfa: MfaState,
    /// Optional active business scope.
    #[serde(default)]
    pub active_scope: Option<ActiveScope>,
}

impl SessionContext {
    /// Creates session context for an authentication method with default MFA state.
    pub fn for_auth_method(auth_method: AuthMethod) -> Self {
        Self {
            auth_method,
            mfa: MfaState::default(),
            active_scope: None,
        }
    }
}
