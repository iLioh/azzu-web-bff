# Implementation status

## Implemented and validated locally

- .NET 8 solution with API, Application, Domain, Infrastructure and Contracts projects.
- Web BFF route skeleton matching the validated Angular contract.
- Cookie/OIDC boundary, CSRF filter, correlation middleware, security headers, rate limiting, idempotency-key validation and RFC 9457 error handling through `IProblemDetailsService`.
- Explicit `(issuer, subject) -> customerId` mapping port with fail-closed unavailable adapter and distinct 401/403/503 outcomes.
- Authentication Context claims challenge skeleton for Entra External ID step-up; real-tenant validation remains pending.
- Session expiration is read from the authenticated ticket, and the session cookie is `__Host-AzzuSession`.
- Ports for Banking Services and customer security. The only registered adapters explicitly return an unavailable-dependency problem.
- Secure multi-stage Dockerfile using the built-in non-root ASP.NET container user.
- Tests for health, OIDC configuration, ticket expiry, session cleanup, identity mapping outcomes, CSRF, Problem Details, idempotency-key enforcement and step-up challenge construction.

Validation run:

~~~text
dotnet build Azzu.WebBff.sln -c Release
Result: 0 warnings, 0 errors

dotnet test Azzu.WebBff.sln -c Release --no-restore
Result: 12 passed, 0 failed
~~~

## Intentionally not implemented

- Entra External ID app registration and runtime secret configuration.
- Distributed server-side token/session store and shared Data Protection keys.
- Customer mapping and Banking Services adapters, durable idempotency, and all access to core/Tailscale/PostgreSQL.
- Azure resources, Kubernetes manifests, Front Door, APIM, Key Vault bindings, DNS and CI deployment.
- Any change to Mobile or apimovil.azzu.tech.

The API blocks production startup until the session/token store and Data Protection strategy are implemented. This is intentional defense-in-depth, not a deployment failure to bypass.

## Next technical gate

Approve the adapter and identity-link contracts, then validate OIDC/Authentication Context against the real External ID tenant before implementing the first read-only Banking Services adapter.
