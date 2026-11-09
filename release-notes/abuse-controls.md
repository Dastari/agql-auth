# Stream: abuse-controls

Abuse and rate-limit controls for credential and request flows. All seven
findings share one design. Credential checks reserve (count) the attempt with
an atomic CAS before verifying anything. A success settles the reservation:
the principal bucket is cleared, and only this attempt is refunded from the
client bucket. An attempt that verified nothing is refunded. Tests live in
`src/tests/abuse_controls.rs`. Each new test failed on the unfixed code.

## AUTH-1 (high): a full in-memory store stopped counting credential failures

Password login (unknown, disabled and known users), both rate-limited TOTP
variants and login-code verification now record the attempt against every key
before verification. If the store cannot record it (an error, or a new key in
a full `MemoryAuthRateLimitStore`), the call returns `AuthServiceUnavailable`
before any password, code or TOTP work. Every outcome is then identical, so
there is no uncounted oracle. Every key is evaluated before any is recorded.
A partial record (principal recorded, client refused) is refunded.
`MemoryAuthRateLimitStore` now caps request-initiation flows
(`PasswordResetRequest`, `LoginCodeRequest`, with a 6-hour TTL) at half its
capacity, rounded down, so request spam cannot use the space credential flows
need. Password-reset token consumption keeps check-then-record counting: it
verifies a signed token, so there is nothing to guess.

Tests: `full_store_does_not_make_password_login_an_uncounted_oracle`,
`full_store_does_not_make_totp_verification_an_uncounted_oracle`,
`full_store_does_not_verify_login_codes_uncounted`,
`request_flows_cannot_exhaust_credential_capacity`,
`a_throttled_client_cannot_add_principal_request_state`.

## AUTH-4 (medium): success cleared the shared per-client bucket

Success now clears only the principal bucket, and only if its revision is
still the one the reservation wrote. Otherwise it refunds one attempt, so
newer failures survive. The client bucket gets a refund of this attempt
only: the exact replaced state is restored when nothing else was written
since, otherwise one attempt is removed from the same window and backoff or
lockout is dropped only below its threshold. Repeated successes from a shared
NAT address leave no client state. Failures from other principals at that
address stay counted. The same fix applies to login-code verification, both
TOTP variants and (through `clear_rate_limit_attempts`, now principal-only)
password-reset token consumption.

Tests: `successful_login_does_not_reset_the_shared_client_bucket`,
`successful_totp_does_not_reset_the_shared_client_bucket`,
`successful_login_code_does_not_reset_the_shared_client_bucket`,
`consumed_reset_token_does_not_reset_the_shared_client_bucket`,
`shared_client_successes_never_accumulate_client_state`.

## AUTH-6 (medium): TOTP attempt budget was check-then-verify

TOTP verification uses the same reservation. Each CAS rechecks backoff and
lockout against the state it replaces, so a concurrent burst can verify at
most `max_attempts_before_lockout` codes per window. Password login and
login-code verification have the same bound. Invalid host-supplied options or
secrets are rejected before anything is counted. A replayed step stays
counted.

Tests: `concurrent_totp_burst_cannot_overrun_the_lockout_budget` (both
variants, 16 concurrent attempts, budget 3: 16 were verified before the fix),
`concurrent_password_burst_cannot_overrun_the_lockout_budget` (12 Argon2
verifications before the fix, 3 after).

## AUTH-7 (low): request flows recorded the principal before the client could deny

`should_process_password_reset_request` and `should_process_login_code_request`
evaluate every key first. They record nothing and return `Ok(false)` if any key
is in backoff or lockout. They record only when all keys admit, and they
refund partial records on a lost race or store error.

Test: `a_throttled_client_cannot_add_principal_request_state` (10 entries
before the fix, 2 after); updated
`capacity_failure_denies_request_admission_without_issuing_authority`.

## AUTH-8 (low): principal bucket keyed on raw input, not the resolved account

Password login looks the account up first. A known account is counted against
an account key derived from its stable local user ID (hash of
`password_login:account:<id>`, bucket `Principal`), so every spelling or alias
the user store accepts shares one budget. An unknown principal is still
counted against its normalized input. The `account` segment can never come
from the `principal` key form, so the two kinds of key cannot collide. This is
one reservation, as for AUTH-1. Request flows keep the submitted principal,
because they must not look the account up.

Test: `principal_aliases_share_one_account_budget`.

## AUTH-9 (low): account-state oracles in password login

Disabled accounts now verify their real stored hash. A wrong password returns
`InvalidCredentials`. Only the correct password returns `UserDisabled`. Both
outcomes stay counted, never clear counters and never issue a session. Some
stored hashes cannot be verified with real Argon2 work: unparsable strings,
other algorithms, invalid parameters, a missing hash, or a salt shorter than 8
bytes. These now do one dummy-hash verification, return `InvalidCredentials`
and count. The 0.19.2 guarantees hold: comparable work, counting, and no
clear or session for disabled users. `docs/password-login-review.md` now
states this.

Tests: `disabled_state_requires_the_correct_password`,
`unverifiable_stored_hashes_do_dummy_work_and_count`; updated
`rejection_contract`, `concurrent_contract`, `independent_buckets_contract`
and `disabled_work_and_public_error_are_preserved_without_rate_limits`.

## #38 (`src/util.rs` bullet): unbounded challenge and TOTP options

These inputs now fail closed:

- `LoginChallengeOptions.code_length` must be 6 to 12, and `max_attempts`
  must be 1 to 10. Six digits with at most ten guesses is at most a
  1-in-100,000 chance per challenge.
- `TotpOptions.period_seconds` must be 15 to 300, and `allowed_skew` at most
  2 (RFC 6238 suggests one step).

Violations return `InvalidConfiguration`. `generate_totp_secret` accepts 20 to
64 bytes. 160 bits is the length RFC 4226 recommends and matches the HMAC-SHA1
output. 64 bytes is the HMAC-SHA1 block size; longer keys only get hashed
down. Provisioning and verification reject decoded secrets shorter than 16
bytes (128 bits, the RFC 4226 minimum), including empty ones, with
`InvalidTotpSecret`. The verification floor is 128 rather than 160 bits so
that existing enrollments at the RFC minimum keep working.

Tests: `login_challenge_options_are_bounded`,
`totp_options_and_secrets_are_bounded`; updated
`numeric_login_codes_are_ascii_digits_and_requested_length` (it used
`code_length = 1`).

## Changelog

### Security

- Credential attempts (password login, TOTP, login codes) are counted before
  verification. A rate-limit store that cannot record an attempt now fails
  closed before any secret is checked, instead of verifying uncounted.
- Concurrent bursts can no longer verify more attempts than the lockout
  budget allows. This applies to TOTP, password login and login codes.
- A successful login, TOTP check, login code or reset-token consumption no
  longer resets the shared per-client bucket. It refunds only its own attempt.
- Password-reset and login-code requests no longer record the principal
  bucket when the client bucket denies the request.
- Password login counts a known account by its local user ID, so aliases
  accepted by the user store share one lockout budget.
- `USER_DISABLED` is returned only after the correct password. A stored hash
  that cannot be verified does dummy Argon2 work and returns
  `INVALID_CREDENTIALS`.

### Fixed

- `MemoryAuthRateLimitStore` reserves at least half its capacity for
  credential flows. Request flows may hold at most `capacity / 2` entries.
- Saturation of the password work pool refunds the reserved attempt, because
  nothing was verified.
- The `password-login-rejection` example now gives the store and the service
  the same clock. With a `FixedClock` service and a system-clock store it
  failed with "replacement is already expired".

### Added

- Bounds for `LoginChallengeOptions` (`code_length` 6 to 12, `max_attempts` 1
  to 10) and `TotpOptions` (`period_seconds` 15 to 300, `allowed_skew` 0 to
  2).
- TOTP secret bounds: generation takes 20 to 64 bytes, and provisioning and
  verification require at least 16 bytes.

### Breaking

- A disabled account with a wrong password now returns `INVALID_CREDENTIALS`,
  not `USER_DISABLED`.
- An unparsable stored password hash now returns `INVALID_CREDENTIALS`. It
  used to return `PasswordHashing` (`AUTH_SERVICE_UNAVAILABLE`).
- Rate-limit store failures during credential flows occur before password or
  code work.
- Success no longer clears the client bucket.
- Password-login counters for known accounts use a new key, derived from the
  user ID.
- Request-initiation flows may use at most half of a
  `MemoryAuthRateLimitStore`. With capacity 1 they always fail closed.
- Option and TOTP secret bounds (see Added) reject values that used to be
  accepted.
- Invalid TOTP options or secrets are reported before the rate-limit check.

## Migration notes

- **Error codes.** Clients that relied on `USER_DISABLED` for a disabled
  account with any password now get `INVALID_CREDENTIALS` unless the password
  is correct. Accounts with corrupt or non-Argon2 stored hashes now get
  `INVALID_CREDENTIALS`, not `AUTH_SERVICE_UNAVAILABLE`. Use host logs or
  data checks to find them; the login path no longer signals them.
- **Durable rate-limit stores.** The trait and `AuthRateLimitKey`,
  `AuthRateLimitState` and `AuthRateLimitSnapshot` are unchanged, and no
  schema migration is needed. Adapters now see new but contract-conforming
  writes:
  - every credential attempt runs CAS on each key before verification;
  - a refund runs CAS that restores an older state or lowers `attempts`;
  - `clear_auth_rate_limit_state(key, Some(rev))` may delete a record created
    moments earlier.

  Adapters that already pass the conformance list need no change. Run the
  refund case added to `docs/abuse-protection.md`.
- **Counter continuity.** After upgrade, existing password-login principal
  counters for known accounts, keyed by the raw principal, are no longer
  consulted. They expire by their TTL (1 hour by default). Client and
  unknown-principal counters carry over.
- **In-memory store sizing.** Hosts that size `MemoryAuthRateLimitStore` for a
  request-heavy load should know that request flows get half the capacity.
  Very small test capacities (1) reject every request flow.
- **Login challenges.** `create_login_challenge` returns `InvalidConfiguration`
  when `code_length` is outside 6 to 12 or `max_attempts` is outside 1 to 10.
  Adjust any custom `LoginChallengeOptions`.
- **TOTP.** `period_seconds` must be 15 to 300 and `allowed_skew` at most 2,
  otherwise `InvalidConfiguration`. `generate_totp_secret(n)` needs
  `20 <= n <= 64` (most callers use 20). Factors enrolled with secrets shorter
  than 16 bytes, such as 80-bit (10-byte) secrets, now fail with
  `INVALID_TOTP_SECRET` and must be re-enrolled. Plan a re-enrollment prompt
  before upgrading.
- **Behaviour under concurrency.** An in-flight attempt counts toward
  thresholds until it resolves. Concurrent attempts on one bucket can see a
  transient `RATE_LIMITED` that a success then removes. With the default
  policy this needs three or more simultaneous in-flight attempts from one
  address or for one account.
- **Exhaustive matches and struct literals.** None changed. No public type,
  variant, field or config default was added or removed.
