# agql-auth

A reusable authentication library for `async-graphql` applications.

## Scope

This crate provides:

- Argon2 password hashing and verification
- short-lived JWT access tokens
- rotated opaque refresh tokens
- database-agnostic storage traits
- `async-graphql` request context helpers
- `async-graphql` guards for auth and roles
- WebSocket `connection_init` authentication support

## Core Types

- `AuthService<U, R>`
- `UserStore`
- `RefreshTokenStore`
- `AuthUser`
- `AuthPayload`
- `RequireAuth`
- `RequireAnyRole`
- `RequireAllRoles`

## Intended Integration

HTTP GraphQL:

- read bearer token or cookie at the transport layer
- validate with `AuthService`
- insert `AuthUser` into `async_graphql::Request`

Subscriptions:

- read `connection_init.payload`
- authenticate with `authenticate_connection_init_value`
- merge returned `async_graphql::Data` into subscription context

## Status

This is a reusable crate scaffold intended for future projects. It is focused on auth primitives and `async-graphql` integration, not on owning your application's database schema or transport bootstrap.

## License

License not selected yet.
