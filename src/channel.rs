use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Host-verified channel identity attached to request data.
///
/// `agql-auth` does not verify certificates, signatures, or transport
/// bindings. Hosts verify the channel first, then inject this bag for guards
/// and resolvers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelIdentity {
    /// Host-defined channel scheme, such as `"mtls"`, `"spiffe"`, or `"hmac"`.
    pub scheme: String,
    /// Stable subject asserted by the verified channel.
    pub subject: String,
    /// Opaque host claims such as certificate fingerprint or serial number.
    #[serde(default)]
    pub claims: BTreeMap<String, String>,
}

impl ChannelIdentity {
    /// Creates a channel identity with no extra claims.
    pub fn new(scheme: impl Into<String>, subject: impl Into<String>) -> Self {
        Self {
            scheme: scheme.into(),
            subject: subject.into(),
            claims: BTreeMap::new(),
        }
    }

    /// Adds a host-defined claim.
    pub fn with_claim(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.claims.insert(key.into(), value.into());
        self
    }
}
