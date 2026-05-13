use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthMethod {
    #[default]
    Password,
    EmailCode,
    SmsCode,
    TotpStepUp,
    ServiceToken,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MfaState {
    pub satisfied: bool,
    pub methods: Vec<MfaMethod>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MfaMethod {
    Totp,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveScope {
    pub tenant_id: Option<String>,
    pub organization_id: Option<String>,
    pub catalog_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionContext {
    #[serde(default)]
    pub auth_method: AuthMethod,
    #[serde(default)]
    pub mfa: MfaState,
    #[serde(default)]
    pub active_scope: Option<ActiveScope>,
}

impl SessionContext {
    pub fn for_auth_method(auth_method: AuthMethod) -> Self {
        Self {
            auth_method,
            mfa: MfaState::default(),
            active_scope: None,
        }
    }
}
