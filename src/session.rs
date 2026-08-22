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
    pub methods: Vec<MfaFactor>,
}

impl MfaState {
    fn is_default(&self) -> bool {
        !self.satisfied && self.methods.is_empty()
    }
}

/// Supported MFA methods recorded in local session context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MfaFactor {
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
    #[serde(default, skip_serializing_if = "MfaState::is_default")]
    pub mfa: MfaState,
    /// Host-authoritative authentication assurance for this session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance: Option<crate::SessionAssurance>,
    /// Optional active business scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_scope: Option<ActiveScope>,
}

impl SessionContext {
    /// Creates session context for an authentication method with default MFA state.
    pub fn for_auth_method(auth_method: AuthMethod) -> Self {
        Self {
            auth_method,
            mfa: MfaState::default(),
            assurance: None,
            active_scope: None,
        }
    }

    /// Attaches validated host assurance and keeps the compatibility MFA view aligned.
    pub fn with_assurance(mut self, assurance: crate::SessionAssurance) -> Self {
        self.mfa = assurance.mfa_state();
        self.assurance = Some(assurance);
        self
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn default_session_fields_have_a_compact_golden_wire_shape() {
        let context = SessionContext::for_auth_method(AuthMethod::MicrosoftOidc);

        assert_eq!(
            serde_json::to_value(&context).unwrap(),
            json!({ "auth_method": "MicrosoftOidc" })
        );
        assert_eq!(
            serde_json::from_value::<SessionContext>(json!({
                "auth_method": "MicrosoftOidc"
            }))
            .unwrap(),
            context
        );
    }

    #[test]
    fn non_default_session_fields_remain_on_the_wire() {
        let context = SessionContext {
            auth_method: AuthMethod::TotpStepUp,
            mfa: MfaState {
                satisfied: true,
                methods: vec![MfaFactor::Totp],
            },
            assurance: None,
            active_scope: Some(ActiveScope {
                tenant_id: Some("tenant-7".to_string()),
                organization_id: None,
                catalog_id: None,
            }),
        };
        let encoded = serde_json::to_value(&context).unwrap();

        assert_eq!(encoded["mfa"]["satisfied"], true);
        assert_eq!(encoded["mfa"]["methods"], json!(["Totp"]));
        assert_eq!(encoded["active_scope"]["tenant_id"], "tenant-7");
        assert_eq!(
            serde_json::from_value::<SessionContext>(encoded).unwrap(),
            context
        );
    }
}
