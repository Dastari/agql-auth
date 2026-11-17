# Dependency advisories

CI runs `cargo audit` on the committed `Cargo.lock`. An advisory may be ignored
in `.cargo/audit.toml` only with a disposition recorded here. Re-check each
entry at every release and remove it as soon as an upgrade resolves it.

## Resolved in 0.27.0

| Advisory | Crate | Resolution |
|---|---|---|
| RUSTSEC-2026-0386 | tokio 1.53.1 (dev-dependency only) | Upgraded to 1.54.1. |
| RUSTSEC-2023-0071 (direct use) | rsa 0.9.10 | The direct `rsa` dependency was removed; JWKS `n`/`e` are now derived through `jsonwebtoken`. |

## Accepted, pending upstream

| Advisory | Crate | Path |
|---|---|---|
| RUSTSEC-2023-0071 | rsa 0.9.10 | `jsonwebtoken` 11.1.0 `rust_crypto` backend |
| RUSTSEC-2026-0387 | crypto-bigint 0.5.5 | `jsonwebtoken` 11.1.0 → p256/p384 0.13 → elliptic-curve 0.13 |

`jsonwebtoken` 11.1.0 is the latest release and its `rust_crypto` backend still
depends on rsa 0.9 and the p256/p384 0.13 line. Both advisories concern timing
side channels in private-key arithmetic. In `agql-auth` that arithmetic runs
when RS256 access tokens are signed (`AuthConfig::with_rs256_pem`) and when
`ClientJwtSigner` signs `private_key_jwt` assertions with RS256, PS256, ES256 or
ES384. `agql-auth` never performs RSA decryption, the operation the Marvin
attack targets most directly.

Switching `jsonwebtoken` to its `aws_lc_rs` backend is not a safe local fix:
`jsonwebtoken` panics at first use when both backends are enabled, and Cargo
feature unification would enable both in any host whose graph also contains a
`rust_crypto` user such as graphql-orm-router.

Mitigations for hosts with a strict side-channel requirement:

- HS256 local sessions and `client_secret_post` / `client_secret_basic` token
  endpoint authentication do not use the affected arithmetic.
- Keep signing hosts on dedicated hardware where co-tenant microarchitectural
  observation is not possible, and rotate RS256 keys on the schedule in
  [key rotation](key-rotation.md).

Remove both ignores when `jsonwebtoken` releases a `rust_crypto` backend on
rsa 0.10 and the p256/p384 0.14 line.
