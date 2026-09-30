# Security baseline

## Implemented in the skeleton

- Cookie authentication uses the HttpOnly, Secure, host-only `__Host-AzzuSession` cookie.
- OIDC Authorization Code + PKCE is enabled only when authority, client ID and secret are securely configured.
- Tokens are not saved into the cookie or exposed to Angular.
- APIs are authenticated by default; health and OIDC entry points are explicit anonymous exceptions.
- Unsafe requests require an HttpOnly host-only antiforgery cookie plus the readable `XSRF-TOKEN`/`X-XSRF-TOKEN` double-submit pair.
- Sensitive endpoints validate a UUID `Idempotency-Key` and apply a fixed-window rate-limit policy. Durable idempotency remains a Banking Services/Core responsibility.
- Customer context is resolved only through `(iss, sub) -> customerId`; no subject/customer fallback exists.
- Step-up uses an OIDC claims request for Conditional Access Authentication Context and validates the returned `acrs` claim.
- Problem responses contain stable codes and X-Correlation-ID.
- The banking adapter defaults to unavailable, avoiding mock balances or accidental direct database access.
- A production guard rejects a configuration without a distributed session/data-protection design.

## Required before deployment

- Configure OIDC values via Key Vault references and Workload Identity, not appsettings files.
- Implement the distributed encrypted server-side session/token store.
- Configure trusted forwarding proxies before applying forwarded headers.
- Replace unavailable adapters with approved Banking Services ports only.
- Add real-tenant External ID tests, adapter contract tests, authorization-by-object tests, durable idempotency tests and Mobile regression tests.
- Set CSP based on final static host/Front Door origins and test it in report-only mode first.
