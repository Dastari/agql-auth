# Bound OIDC Reauthentication And Step-Up Requests

`OidcProvider` can bind typed reauthentication requirements to the exact
single-use OAuth state created for an authorization request. The provider must
return signed ID-token evidence satisfying that stored policy before the
callback succeeds.

## Trust Boundary

Keep these stages separate:

1. `OidcAuthorizationOptions` says what evidence the host requests.
2. `create_authorization_request_with_options` validates and normalizes the
   options, then persists the versioned `OidcAuthorizationPolicy` with the
   hashed state, nonce, and PKCE verifier.
3. The identity provider authenticates the user and signs an ID token.
4. `handle_callback` atomically consumes the exact state, validates the ID-token
   signature, issuer, audience, nonce, and time claims, then enforces the bound
   policy.
5. `OidcAuthorizationOutcome` tells the host whether the callback was bound to
   typed options and which authentication-time, standard ACR, or exact
   list-valued `acrs` requirement was enforced.
6. The host separately decides whether validated `amr`, scalar `acr`, or
   provider-specific `acrs` evidence satisfies its local assurance/MFA policy.
7. Local session assurance and resource authorization remain authoritative.

Neither `prompt=login`, `max_age`, `iat`, `auth_time`, provider kind, nor a
successful redirect proves MFA or a particular authentication method.

## Generic Recent Reauthentication

```rust
use agql_auth::{
    OidcAuthorizationOptions, OidcIdTokenClaimRequest, OidcPrompt,
};

let options = OidcAuthorizationOptions {
    prompt: vec![OidcPrompt::Login],
    max_age: Some(300),
    acr_values: Vec::new(),
    id_token_claims: vec![OidcIdTokenClaimRequest::EssentialAuthTime],
};
let expected_policy = options.validate()?;

let request = provider
    .create_authorization_request_with_options(&oauth_state_store, options)
    .await?;

// Redirect the browser to request.authorization_url. The request's Debug
// output redacts the complete URL, state, nonce, verifier, and challenge.

let outcome = provider
    .handle_callback(&oauth_state_store, callback_input)
    .await?;

// A step-up endpoint should require the exact expected policy. This rejects a
// callback started through the default/normal-login API.
outcome.authorization.require_bound_policy(&expected_policy)?;
```

`create_authorization_request` remains the compatibility API. It produces the
same PKCE S256, nonce, state, scopes, redirect URI, response type, and response
mode behavior, with no bound authorization policy.

The options surface has no arbitrary query-parameter map, so callers cannot
replace reserved parameters such as `state`, `nonce`, `client_id`, `claims`, or
`redirect_uri`. Prompt values are typed. `max_age` accepts zero and is bounded
by `MAX_OIDC_MAX_AGE_SECONDS`. ACR lists and claim requests have count,
per-value, aggregate, and serialized-size limits; duplicates, whitespace,
controls, blanks, invalid combinations, and noncanonical values fail before
state insertion. Values are percent-encoded exactly once.

## Callback And Clock-Skew Semantics

When `max_age` is present, a numeric, non-negative `auth_time` is mandatory, as
required by OpenID Connect Core. `max_age=0` has the same active-authentication
meaning as `prompt=login`; it still says nothing about MFA.

With provider time `now`, configured skew `s`, and requested maximum age `a`,
the callback accepts:

```text
now - a - s <= auth_time <= now + s
```

Both boundaries are inclusive; one second outside either boundary fails.
Arithmetic and timestamp conversion are checked. `new_with_clock` injects the
clock used for state, cache, future-skew, and max-age decisions so boundary
tests do not depend on wall-clock timing.

An essential `auth_time` request requires the claim even without `max_age`.
An essential standard `acr` request requires a correctly typed scalar equal to
one of its exact case-sensitive values. `acr_values` is the OIDC voluntary
preference parameter and is deliberately not treated as an enforced result.
The crate rejects combining `acr_values` with an individual essential `acr`
claim because OpenID Connect leaves that combination's behavior unspecified.

An essential `acrs` request is separate and requires the provider-returned
bounded string list to contain one exact case-sensitive context. It does not
conflict with scalar `acr` because the claims have different meanings and
types. A matching `acrs` value never supplies a missing or stale `auth_time`.

## Standard `acr` And Provider `acrs`

`ValidatedOidcClaims.acr` is the standard scalar authentication-context class.
`ValidatedOidcClaims.acrs` is a separately typed, bounded string list for
provider-returned authentication-context identifiers. The library never
merges, translates, or labels either as MFA. Malformed, duplicate, blank,
controlled, oversized, scalar, object, or nested `acrs` values fail validation.

For a deterministic exact-context request, add the typed claim alongside any
independent reauthentication requirement:

```rust
let options = OidcAuthorizationOptions {
    prompt: vec![OidcPrompt::Login],
    max_age: Some(300),
    acr_values: Vec::new(),
    id_token_claims: vec![
        OidcIdTokenClaimRequest::EssentialAuthTime,
        OidcIdTokenClaimRequest::EssentialAcrs {
            value: "c1".to_string(),
        },
    ],
};
```

The typed request serializes as an essential `acrs` individual claim request
with singular `"value": "c1"`. Its exact normalized value is persisted in
policy version 2 before OAuth state is issued. After ordinary ID-token checks,
the callback requires the list to contain it and exposes that exact match only
as `OidcAuthorizationOutcome.matched_acrs`.

Microsoft documents `acrs` principally as authentication-context evidence in
access tokens, while Conditional Access authentication context can require an
explicit claims request to trigger deterministic step-up. Token-type optional
claim and Conditional Access behavior must still be configured and proven for
the particular tenant and application. An Entra-oriented host may accept a
validated ID-token `acrs` match only when its separately configured tenant
contract is known to issue it, then exact-allowlist and map that identifier.
Absence remains absence and never implies MFA.

Primary provider references:

- [OpenID Connect Core authentication requests](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
- [OpenID Connect Core individual claim requests](https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests)
- [Microsoft Entra optional claims](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims)
- [Microsoft Entra token claims](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference)
- [Microsoft Entra authentication context](https://learn.microsoft.com/en-us/entra/identity-platform/developer-guide-conditional-access-authentication-context)

## State Storage And Migration

`OAuthLoginState` adds
`authorization_policy: Option<OidcAuthorizationPolicy>`. JSON/document readers
may deploy first: the field uses `serde(default)` and legacy in-flight records
deserialize as `None`. `None` means no requested reauthentication policy; it
never means satisfied. Relational stores should add a nullable JSON/typed
column and return it from atomic consumption:

```sql
ALTER TABLE oauth_states
    ADD COLUMN authorization_policy JSON NULL;
```

The `OAuthStateStore` method signatures do not change. Implementations using
`OAuthLoginState` struct literals must add `authorization_policy: None`.
Version 1 remains canonical for policies without `acrs`. Policies requesting
`acrs` use version 2; version 1 with an `acrs` field, version 2 without it, and
unknown/corrupt versions fail closed. Deploy readers that accept the optional
field before writers that create these step-up requests.

## Long-Lived Operations

Completing this callback proves only that its bound provider request was
satisfied at that moment. WebSockets, subscriptions, queued jobs, and other
long-lived operations must reevaluate local session assurance before each
protected operation and when the assurance-age deadline arrives. A connection
authorized once must not retain elevated access after assurance ages out. See
[WebSocket reauthorization](websocket-reauthorization.md).
