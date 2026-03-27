use serde::{Deserialize, Serialize};
use time::Duration;

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub issuer: String,
    pub audience: String,
    pub jwt_secret: String,
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,
}

impl AuthConfig {
    pub fn new(jwt_secret: impl Into<String>) -> Self {
        Self {
            issuer: "agql-auth".to_string(),
            audience: "agql-auth-clients".to_string(),
            jwt_secret: jwt_secret.into(),
            access_token_ttl: Duration::minutes(15),
            refresh_token_ttl: Duration::days(30),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientMetadata {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}
