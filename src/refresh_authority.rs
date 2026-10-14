//! Authoritative grants for refresh rotation.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{AuthResult, StoredRefreshToken, StoredUser};

/// Source that must authorize refreshable session grants.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RefreshGrantSource {
    /// Legacy records have no trustworthy provenance and cannot refresh.
    #[default]
    Legacy,
    /// Password login derives authority from the current stored user.
    StoredUser,
    /// Host/OIDC issuance requires an explicit host grant authority.
    Host,
}

/// Current host-authorized grants. Rotation always intersects these with the
/// previous refresh record, so neither new roles nor new scopes widen a session.
#[derive(Debug, Clone, Default)]
pub struct CurrentRefreshGrant {
    /// Currently authorized roles.
    pub roles: Vec<String>,
    /// Currently authorized scopes.
    pub scopes: Vec<String>,
}

/// Host authority for custom and external refreshable grants.
#[async_trait]
pub trait RefreshGrantAuthority: Send + Sync {
    /// Reads current durable authority and fails closed on revocation or errors.
    ///
    /// The user has already been loaded and checked for disable/deletion.
    /// Implementations must check provider/grant revocation and tenant membership
    /// as appropriate. This is a read: it must not renew the grant itself.
    async fn current_grant(
        &self,
        previous: &StoredRefreshToken,
        user: &StoredUser,
    ) -> AuthResult<CurrentRefreshGrant>;
}
