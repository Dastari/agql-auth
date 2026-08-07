# Access-Token Scope Claims

Version 0.14 standardizes the access-token wire representation on the OAuth
`scope` claim while preserving the existing `AuthUser::scopes` authorization
API. This document defines the claim contract, compatibility policy, and safe
deployment sequence.

## Contract

New access tokens use a single space-delimited string:

```json
{
  "scope": "users.read users.write"
}
```

The order is the issuer's stable first-seen order after deterministic
deduplication. An access token with no scopes omits `scope`. Once validated,
the example becomes:

```rust
assert_eq!(user.scopes, ["users.read", "users.write"]);
```

This change applies to normal session access tokens and access-token-only
grants. It does not change:

- purpose tokens, which retain their separate `scopes` string array;
- opaque API/service tokens;
- opaque refresh tokens or refresh-store records;
- `AuthUser::scopes`, guards, or `ScopeMatch`; or
- OIDC/provider tokens and provider scope requests.

The signing algorithm is orthogonal. HS256 and RS256 access tokens use the same
claim shape. RS256 private material remains confined to signing; validators and
routers need only the public key or JWKS.

## Compatibility Controls

`AuthConfig` defaults to standard issuance and migration-compatible
validation:

```rust
use agql_auth::{
    AccessTokenScopeClaimFormat, AuthConfig, LegacyScopeClaims,
};

let config = AuthConfig::with_rs256_pem(private_pem, public_pem, key_id)
    .with_access_token_scope_claim_format(
        AccessTokenScopeClaimFormat::Standard,
    )
    .with_legacy_scope_claims(LegacyScopeClaims::Accept);
```

Issuance and validation are deliberately independent:

- `AccessTokenScopeClaimFormat::Standard` emits only `scope` and is the
  default.
- `AccessTokenScopeClaimFormat::LegacyArray` emits only the pre-0.14 `scopes`
  array. It is a temporary rollback and staged-deployment control, not a
  recommended format for new systems.
- `LegacyScopeClaims::Accept` reads a legacy array when it does not conflict
  with a standard claim. This is the default migration policy.
- `LegacyScopeClaims::Reject` rejects any token containing `scopes`, even when
  the array is empty or equivalent to `scope`.

`AuthService::new` rejects legacy issuance combined with legacy rejection,
because a service configured that way could not validate its own tokens.

Independent resource servers set validation policy on their builder:

```rust
use agql_auth::{AccessTokenValidator, LegacyScopeClaims};

let validator = AccessTokenValidator::builder()
    .issuer("agql-auth")
    .audience("agql-auth-clients")
    .rs256_public_pem(public_key_pem)
    .key_id("auth-key-2026-07")
    .legacy_scope_claims(LegacyScopeClaims::Accept)
    .build()?;
```

## Dual Claims

A migration-compatible validator may encounter a token containing both names:

```json
{
  "scope": "users.write users.read",
  "scopes": ["users.read", "users.write"]
}
```

The token is accepted only when legacy support is enabled and both claims
describe the same set. Order and duplicate entries do not create a conflict.
The values exposed through `AuthUser::scopes` follow the standard `scope`
claim's stable order.

Different sets fail closed. This prevents ambiguous authorization when one
consumer prefers `scope` and another prefers `scopes`. `agql-auth` itself never
issues both claims. In strict mode, the mere presence of `scopes` is rejected.

## Grammar And Bounds

Each scope value must be non-empty printable ASCII allowed by the OAuth
scope-token grammar: byte `0x21`, bytes `0x23` through `0x5B`, or bytes `0x5D`
through `0x7E`. Spaces delimit values and therefore cannot occur inside one
value. Double quotes, backslashes, control characters, and non-ASCII bytes are
not accepted.

The same limits apply during issuance and validation:

| Limit | Constant | Value |
| --- | --- | ---: |
| Number of scope values | `MAX_ACCESS_TOKEN_SCOPES` | 256 |
| Bytes in one scope value | `MAX_ACCESS_TOKEN_SCOPE_LENGTH` | 512 |
| Aggregate bytes, including delimiters | `MAX_ACCESS_TOKEN_SCOPE_CLAIM_LENGTH` | 16 KiB |

Standard `scope` must not be an empty string and must use exactly one ASCII
space between values. Leading spaces, trailing spaces, repeated spaces, tabs,
and newlines are invalid. Legacy arrays may be empty during migration. A token
without either claim represents an empty scope set.

Invalid scope claims return the existing coarse invalid-token or token-creation
errors. Rejected values are not copied into diagnostics.

## Deployment Sequence

Inventory every component that reads access JWTs, including routers,
subgraphs, APIs, workers, WebSocket authentication, test fixtures, monitoring,
and gateway policy. Components using `AuthService` or a 0.14
`AccessTokenValidator` already share the compatible decoder; custom decoders
must be updated explicitly.

1. Deploy 0.14 everywhere with `LegacyScopeClaims::Accept`.
2. If any consumer is not ready, keep issuers on
   `AccessTokenScopeClaimFormat::LegacyArray` temporarily.
3. Verify every consumer accepts a standard-only token and maps it to the same
   authorization set.
4. Switch all issuers to `AccessTokenScopeClaimFormat::Standard`.
5. Keep legacy acceptance for at least the maximum old access-token TTL plus
   configured validation leeway. Include access-token-only grants with custom
   TTLs when calculating the window.
6. Set `LegacyScopeClaims::Reject` on every local and independent validator.
7. Confirm legacy-only and dual-claim tokens are rejected while standard-only
   tokens continue to authorize correctly.

Do not use refresh-token TTL as the wait period. A refresh operation issues a
new access token in the issuer's current format.

## Rollback

Rollback does not require a database or token-store change. Set issuers back to
`AccessTokenScopeClaimFormat::LegacyArray` and validators to
`LegacyScopeClaims::Accept`. Tokens already issued with `scope` remain valid in
the compatible mode. Fix the incompatible consumer, then repeat the standard
issuance switch and full expiry window before selecting strict rejection.

## Acceptance Checks

Before completing a deployment, verify at least:

- standard-only tokens succeed through every HTTP and WebSocket auth path;
- legacy-only tokens succeed only during the declared migration window;
- equivalent dual claims succeed only in compatibility mode;
- conflicting dual claims fail in every validator;
- malformed and oversized claims fail without leaking claim values;
- empty scope sets remain unauthorised for scoped operations;
- purpose tokens still use and validate their purpose-specific `scopes`
  array; and
- RS256 consumers validate with public material only.

The crate test suite covers these claim-shape and validation boundaries. Host
deployment tests remain responsible for proving that every real consumer has
adopted the same policy.
