//! Token-endpoint client authentication shared by [`crate::OidcProvider`] and
//! [`crate::OAuth2Provider`].

use std::fmt;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::{AuthError, AuthResult};

/// Largest accepted client JWT lifetime (15,777,000 seconds, about six months).
///
/// This is the most lenient documented provider maximum (Sign in with Apple).
/// Signers mint a fresh JWT for every token request, so short lifetimes are
/// recommended; [`ClientJwtClaims::new`] defaults to five minutes.
pub const MAX_CLIENT_JWT_LIFETIME_SECONDS: i64 = 15_777_000;

/// RFC 7523 client assertion type for `private_key_jwt`.
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// `application/x-www-form-urlencoded` component encoding for Basic credentials
/// (RFC 6749 section 2.3.1). Only unreserved characters stay literal.
const FORM_COMPONENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// How the client authenticates at the token endpoint.
///
/// The default, [`Self::ClientSecretPost`], preserves earlier behavior: the
/// client ID is always sent in the form body, and a client secret (static or
/// signed) is added when configured. A client without a secret is a public
/// client.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TokenEndpointAuthMethod {
    /// `client_secret_post`: `client_id` and optional `client_secret` in the form body.
    #[default]
    ClientSecretPost,
    /// `client_secret_basic`: HTTP Basic `client_id:client_secret`, each
    /// form-urlencoded first. Requires a static or signed client secret and an
    /// [`crate::OidcHttpClient`] that supports request headers.
    ClientSecretBasic,
    /// RFC 7523 / OIDC Core `private_key_jwt`: a fresh signed
    /// `client_assertion` per request. Requires a [`ClientJwtSigner`] and no
    /// static client secret.
    PrivateKeyJwt,
}

/// Signature algorithm for host-supplied client JWT keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ClientJwtAlgorithm {
    /// ECDSA P-256 with SHA-256. Use a PKCS#8 PEM P-256 private key.
    ES256,
    /// ECDSA P-384 with SHA-384. Use a PKCS#8 PEM P-384 private key.
    ES384,
    /// RSASSA-PKCS1-v1_5 with SHA-256. Use a PKCS#1 or PKCS#8 PEM RSA private key.
    RS256,
    /// RSASSA-PSS with SHA-256. Use a PKCS#1 or PKCS#8 PEM RSA private key.
    PS256,
}

impl ClientJwtAlgorithm {
    fn jwt_algorithm(self) -> Algorithm {
        match self {
            Self::ES256 => Algorithm::ES256,
            Self::ES384 => Algorithm::ES384,
            Self::RS256 => Algorithm::RS256,
            Self::PS256 => Algorithm::PS256,
        }
    }
}

/// Claims and header values for a host-signed client JWT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ClientJwtClaims {
    /// `kid` header value identifying the key at the provider.
    pub key_id: Option<String>,
    /// `iss` claim. For `private_key_jwt` this is the client ID; Sign in with
    /// Apple uses the developer team ID.
    pub issuer: String,
    /// `sub` claim, normally the client ID.
    pub subject: String,
    /// `aud` claim. `None` uses the token endpoint URL, as OIDC Core recommends
    /// for `private_key_jwt`. Sign in with Apple requires `https://appleid.apple.com`.
    pub audience: Option<String>,
    /// Lifetime of each minted JWT (`exp - iat`).
    pub lifetime: Duration,
}

impl ClientJwtClaims {
    /// Creates claims with no `kid`, the token endpoint audience, and a
    /// five-minute lifetime.
    pub fn new(issuer: impl Into<String>, subject: impl Into<String>) -> Self {
        Self {
            key_id: None,
            issuer: issuer.into(),
            subject: subject.into(),
            audience: None,
            lifetime: Duration::minutes(5),
        }
    }

    /// Sets the `kid` header.
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Sets a fixed `aud` claim.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Sets the lifetime of each minted JWT.
    pub fn with_lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    fn validate(&self) -> AuthResult<()> {
        if self.issuer.trim().is_empty() || self.subject.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "client JWT issuer and subject must not be empty".to_string(),
            ));
        }
        if self
            .key_id
            .as_deref()
            .is_some_and(|kid| kid.trim().is_empty())
        {
            return Err(AuthError::InvalidConfiguration(
                "client JWT key_id must not be empty when set".to_string(),
            ));
        }
        if self
            .audience
            .as_deref()
            .is_some_and(|audience| audience.trim().is_empty())
        {
            return Err(AuthError::InvalidConfiguration(
                "client JWT audience must not be empty when set".to_string(),
            ));
        }
        if self.lifetime <= Duration::ZERO
            || self.lifetime > Duration::seconds(MAX_CLIENT_JWT_LIFETIME_SECONDS)
        {
            return Err(AuthError::InvalidConfiguration(
                "client JWT lifetime must be positive and at most the supported maximum"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// Host-supplied private key that mints a fresh client JWT per token request.
///
/// With [`TokenEndpointAuthMethod::PrivateKeyJwt`] the JWT is the RFC 7523
/// `client_assertion` and carries a random `jti`. With
/// [`TokenEndpointAuthMethod::ClientSecretPost`] or
/// [`TokenEndpointAuthMethod::ClientSecretBasic`] it is used as the
/// `client_secret` value (a signed client secret, as Sign in with Apple
/// requires) and carries exactly `iss`, `sub`, `aud`, `iat` and `exp`.
///
/// The key stays in memory: it is never serialized, never logged and is
/// redacted from `Debug`. The PEM input is not retained after parsing.
#[derive(Clone)]
pub struct ClientJwtSigner {
    algorithm: ClientJwtAlgorithm,
    key: Arc<EncodingKey>,
    claims: ClientJwtClaims,
}

impl fmt::Debug for ClientJwtSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientJwtSigner")
            .field("algorithm", &self.algorithm)
            .field("key", &"[redacted]")
            .field("claims", &self.claims)
            .finish()
    }
}

#[derive(Serialize)]
struct ClientJwtPayload<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    jti: Option<String>,
}

impl ClientJwtSigner {
    /// Parses a PEM private key and validates the claim template.
    ///
    /// A probe signature is produced so a key that does not match the selected
    /// algorithm (for example a P-384 key for ES256) fails here rather than at
    /// the first sign-in.
    pub fn from_pem(
        algorithm: ClientJwtAlgorithm,
        private_key_pem: &[u8],
        claims: ClientJwtClaims,
    ) -> AuthResult<Self> {
        claims.validate()?;
        let key = match algorithm {
            ClientJwtAlgorithm::ES256 | ClientJwtAlgorithm::ES384 => {
                EncodingKey::from_ec_pem(private_key_pem)
            }
            ClientJwtAlgorithm::RS256 | ClientJwtAlgorithm::PS256 => {
                EncodingKey::from_rsa_pem(private_key_pem)
            }
        }
        .map_err(|_| {
            AuthError::InvalidConfiguration(
                "client JWT private key is not a valid PEM key for the algorithm".to_string(),
            )
        })?;
        let signer = Self {
            algorithm,
            key: Arc::new(key),
            claims,
        };
        signer
            .sign(OffsetDateTime::UNIX_EPOCH, "probe", false)
            .map_err(|_| {
                AuthError::InvalidConfiguration(
                    "client JWT private key does not match the algorithm".to_string(),
                )
            })?;
        Ok(signer)
    }

    /// Selected signature algorithm.
    pub fn algorithm(&self) -> ClientJwtAlgorithm {
        self.algorithm
    }

    /// Claim template used for each minted JWT.
    pub fn claims(&self) -> &ClientJwtClaims {
        &self.claims
    }

    /// Mints a client JWT issued at `now`.
    ///
    /// `default_audience` is used when the claim template has no fixed
    /// audience. `include_jti` adds a random `jti` (required for
    /// `private_key_jwt`).
    pub fn sign(
        &self,
        now: OffsetDateTime,
        default_audience: &str,
        include_jti: bool,
    ) -> AuthResult<String> {
        let iat = now.unix_timestamp();
        let exp = iat
            .checked_add(self.claims.lifetime.whole_seconds())
            .ok_or_else(|| AuthError::TokenCreation("client JWT expiry overflowed".to_string()))?;
        let jti = include_jti.then(|| {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            URL_SAFE_NO_PAD.encode(bytes)
        });
        let payload = ClientJwtPayload {
            iss: &self.claims.issuer,
            sub: &self.claims.subject,
            aud: self.claims.audience.as_deref().unwrap_or(default_audience),
            iat,
            exp,
            jti,
        };
        let mut header = Header::new(self.algorithm.jwt_algorithm());
        header.typ = Some("JWT".to_string());
        header.kid = self.claims.key_id.clone();
        encode(&header, &payload, &self.key)
            .map_err(|_| AuthError::TokenCreation("client JWT signing failed".to_string()))
    }
}

/// Validates the combination of auth method and credential sources.
pub(crate) fn validate_client_authentication(
    prefix: &str,
    method: TokenEndpointAuthMethod,
    client_secret: Option<&str>,
    client_jwt: Option<&ClientJwtSigner>,
) -> AuthResult<()> {
    if client_secret.is_some() && client_jwt.is_some() {
        return Err(AuthError::InvalidConfiguration(format!(
            "{prefix} must not configure both client_secret and client_jwt"
        )));
    }
    match method {
        TokenEndpointAuthMethod::ClientSecretPost => Ok(()),
        TokenEndpointAuthMethod::ClientSecretBasic => {
            if client_secret.is_none() && client_jwt.is_none() {
                return Err(AuthError::InvalidConfiguration(format!(
                    "{prefix} client_secret_basic requires client_secret or client_jwt"
                )));
            }
            Ok(())
        }
        TokenEndpointAuthMethod::PrivateKeyJwt => {
            if client_jwt.is_none() {
                return Err(AuthError::InvalidConfiguration(format!(
                    "{prefix} private_key_jwt requires client_jwt"
                )));
            }
            Ok(())
        }
    }
}

/// Header and form parameters authenticating one token request.
pub(crate) struct ClientAuthentication {
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) form: Vec<(String, String)>,
}

/// Builds the client-authentication parts of a token request.
///
/// Secret values exist only in the returned request parts.
pub(crate) fn client_authentication(
    method: TokenEndpointAuthMethod,
    client_id: &str,
    client_secret: Option<&str>,
    client_jwt: Option<&ClientJwtSigner>,
    token_endpoint: &str,
    now: OffsetDateTime,
) -> AuthResult<ClientAuthentication> {
    let secret = match (method, client_secret, client_jwt) {
        (TokenEndpointAuthMethod::PrivateKeyJwt, _, _) => None,
        (_, Some(secret), _) => Some(secret.to_string()),
        (_, None, Some(signer)) => Some(signer.sign(now, token_endpoint, false)?),
        (_, None, None) => None,
    };
    let mut headers = Vec::new();
    let mut form = Vec::new();
    match method {
        TokenEndpointAuthMethod::ClientSecretPost => {
            form.push(("client_id".to_string(), client_id.to_string()));
            if let Some(secret) = secret {
                form.push(("client_secret".to_string(), secret));
            }
        }
        TokenEndpointAuthMethod::ClientSecretBasic => {
            let secret = secret.ok_or_else(|| {
                AuthError::InvalidConfiguration(
                    "client_secret_basic requires a client secret".to_string(),
                )
            })?;
            let credentials = format!(
                "{}:{}",
                utf8_percent_encode(client_id, FORM_COMPONENT_ENCODE_SET),
                utf8_percent_encode(&secret, FORM_COMPONENT_ENCODE_SET)
            );
            headers.push((
                "Authorization".to_string(),
                format!("Basic {}", STANDARD.encode(credentials)),
            ));
        }
        TokenEndpointAuthMethod::PrivateKeyJwt => {
            let signer = client_jwt.ok_or_else(|| {
                AuthError::InvalidConfiguration("private_key_jwt requires client_jwt".to_string())
            })?;
            form.push(("client_id".to_string(), client_id.to_string()));
            form.push((
                "client_assertion_type".to_string(),
                CLIENT_ASSERTION_TYPE_JWT_BEARER.to_string(),
            ));
            form.push((
                "client_assertion".to_string(),
                signer.sign(now, token_endpoint, true)?,
            ));
        }
    }
    Ok(ClientAuthentication { headers, form })
}
