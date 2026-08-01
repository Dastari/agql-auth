# Session Assurance And Recent MFA

Session assurance records what the host knows about an authentication event,
not what an untrusted request says happened.

## Trust Boundary

The flow has four distinct stages:

1. An identity provider may report `auth_time`, `amr`, and `acr` in a signed ID
   token.
2. `OidcProvider` validates the ID token and exposes strictly typed, bounded,
   normalized values on `ValidatedOidcClaims`.
3. The host's `ClaimsMapper` applies provider-specific policy. Only the host can
   return `MappedClaims.assurance = Some(...)` with `MfaAcceptance::Satisfied`.
4. Resource authorization evaluates the locally signed access token with
   `RecentMfaPolicy` and an injected `Clock`.

Provider AMR/ACR strings have no universal meaning. The built-in mappers never
infer MFA, and this crate defines no provider-specific MFA vocabulary.

## Issuance And Refresh Continuity

Create `SessionAssurance` with the genuine authentication time, normalized
methods, optional ACR/context, and the host's acceptance decision. Use
`issue_assured_user_session` or attach it to `SessionContext` and call
`issue_session_for_user_with_metadata`.

The access token receives exact `auth_time`, `amr`, and `acr` claims plus the
MFA acceptance in its signed session context. Refresh stores assurance inside
the session context and copies it exactly through every rotation. Refresh never
sets authentication time to token issue time.

`RefreshableTokenMetadata` deliberately allows only tenant, organization,
actor, and correlation values. Every rotated token gets a new `jti`, expiry,
and purpose. Confirmation and resource bindings, plus arbitrary additional
claims, are excluded because they may not apply to the next token.

## Step-Up

After the host verifies a new factor, call `step_up_session` with the current
refresh token, `StepUpAuthentication`, client metadata, and a trusted clock.
The operation atomically rotates that refresh token and records `clock.now()`
as the new genuine step-up time. It keeps the same session family and does not
alter unrelated sessions for the user.

Do not call the step-up API before factor verification succeeds. The API call
is the host's authoritative assertion that the event satisfies local MFA
policy.

`StepUpAuthentication` is provider-neutral. A host may record normalized
methods such as password plus TOTP, an independently verified OIDC
reauthentication, WebAuthn, or a host-defined assurance method/context. The
host verifies the password, code, authenticator assertion, or provider response
first; `step_up_session` does not verify external evidence and never accepts a
raw provider token.

## Resource Policy

`RecentMfaPolicy::evaluate` requires:

- authoritative assurance and satisfied MFA state;
- signed token `auth_time`, AMR, and ACR consistent with session assurance;
- configured AMR/ACR allowlists using explicit `All` or `Any` semantics;
- `auth_time` no farther in the future than bounded clock skew;
- age at or below the configured inclusive maximum;
- checked time arithmetic.

All failures return the same safe public message and a stable denial code.
`internal_detail()` is for protected server diagnostics and is omitted from
`Debug`. Never attach raw access, refresh, or provider tokens to errors, hooks,
or decision events.

Legacy sessions with no assurance continue to refresh. They fail only when a
host opts a resource into `RecentMfaPolicy`, and then fail closed until genuine
step-up.

## Declarative Requirements And Evaluation

`AssurancePolicyId` is a stable configuration identity, not an ACR or provider
name. Declare an `AssuranceRequirement`, register its `RecentMfaPolicy` in an
`AssurancePolicySet`, and evaluate with the current decoded user plus an
injected `Clock`:

```rust
let policy_id = AssurancePolicyId::new("interactive.recent-auth")?;
let requirement = AssuranceRequirement::new(policy_id.clone());

let mut policies = AssurancePolicySet::new();
policies.insert(policy_id, recent_mfa_policy);

let evaluation = policies.evaluate(&requirement, user.as_ref(), clock.as_ref());
```

The clock is read exactly once. `AssuranceEvaluation` includes that
`ServerEvaluationTime`; a satisfied decision also includes `AuthenticatedAt`
and the inclusive `SatisfiedUntil` boundary. At exactly `SatisfiedUntil` the
policy is satisfied; one clock tick later it requires step-up. Future times are
accepted only through the configured inclusive skew boundary.

Evaluation states map without message parsing:

| State | GraphQL category | Meaning |
|-------|------------------|---------|
| `Satisfied` | none | Execute only after the operation's other authorization checks pass |
| `Unauthenticated` | `UNAUTHENTICATED` | No user session was supplied |
| `StepUpRequired` | `STEP_UP_REQUIRED` | A session exists but assurance is missing, stale, invalid, or disallowed |
| `Forbidden` | `FORBIDDEN` | The policy is absent or cannot be evaluated safely |

`AssuranceDenialCode` retains a more specific machine-readable reason for
telemetry and controlled client behavior. Human-readable messages are not part
of the decision contract.

## Safe Client Status

`SessionAssuranceStatus::from_user` exposes only whether a user is
authenticated, a structurally claim-consistent authentication time, and MFA
satisfaction. It deliberately omits session IDs, method/ACR/context values,
all token claims, access and refresh tokens, secrets, and provider payloads.
Treat this status as advisory UI input and reevaluate the actual operation on
the server.

## WebSockets And Long-Lived Work

Reevaluate recent-MFA policy when a protected operation begins and when the
assurance-age deadline arrives. A connection that was authorized at startup
must not retain high-assurance access forever. See
[WebSocket reauthorization](websocket-reauthorization.md).
