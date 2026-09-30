# Web BFF hardening report — 2026-09-30

## Validation result

~~~text
dotnet format Azzu.WebBff.sln --verify-no-changes --no-restore
Result: success

dotnet build Azzu.WebBff.sln -c Release --no-restore
Result: success, 0 warnings, 0 errors

dotnet test Azzu.WebBff.sln -c Release --no-build --no-restore
Result: 12 passed, 0 failed, 0 skipped
~~~

## Exact changes

1. Removed the `subject -> customerId` fallback and introduced `ICustomerIdentityMapping` keyed by validated `issuer + subject`.
2. Added distinct outcomes: invalid session `401` with cookie cleanup; valid but unlinked identity `403` without logout; mapping dependency unavailable `503` without logout.
3. Made `/api/v1/auth/step-up` authenticated.
4. Replaced `acr_values=mfa` with an OIDC `claims` request for an operation-mapped Conditional Access Authentication Context (`id_token.acrs`).
5. Persisted the required Authentication Context ID in protected OIDC state and validate the returned `acrs` claim in `OnTokenValidated`.
6. Replaced manual exception JSON serialization with `IProblemDetailsService` and `application/problem+json`.
7. Unified the session cookie name as `__Host-AzzuSession`.
8. Made `expiresAtUtc` come from the authenticated ticket's `ExpiresUtc`; no synthetic `UtcNow + timeout` value remains.
9. Separated the host-only HttpOnly antiforgery cookie from Angular's readable `XSRF-TOKEN`; unsafe requests continue to require `X-XSRF-TOKEN`.
10. Documented and tested that the BFF idempotency filter validates/forwards a UUID only; durable deduplication remains outside the BFF.
11. Expanded tests to cover ticket expiry, cookie cleanup, unlinked identity, mapping outage, missing identity claims, CSRF, Problem Details media type, missing/valid idempotency keys, authenticated step-up and Authentication Context claims construction/validation.
12. Added design documents for the future `itforbanking-api` adapter, identity mapping and Entra External ID step-up.

## Pending risks and gates

- The current identity-mapping adapter deliberately returns unavailable. The authoritative Banking Services identity-link contract must be approved and implemented.
- OIDC discovery, callbacks, Conditional Access policy evaluation and actual `acrs` claims must be tested against the real Entra External ID tenant.
- Authentication Context IDs are intentionally absent from source configuration and must be provisioned/mapped through approved runtime configuration.
- Production still requires a distributed encrypted server-side session/token store and shared Data Protection keys; startup remains fail-closed without them.
- The adapter contract, service authentication, ownership checks, timeouts and error mapping for `itforbanking-api` are not yet proven.
- Persistent idempotency, atomic write/result storage and replay belong in Banking Services/Core and remain unimplemented.
- Object-level authorization and Mobile regression tests are required before exposing banking operations.
- Conditional Access/Authentication Context licensing, cost and tenant capability need explicit confirmation.

## Scope confirmation

No Azure resource, Entra tenant configuration, Mobile code, PostgreSQL configuration or Tailscale component was changed. Banking Services were not integrated and nothing was deployed.
