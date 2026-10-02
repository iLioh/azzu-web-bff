# Implementation status

## Current handoff — 2026-10-02

The single current resource/commit/image inventory is [azzu-cloud-infra README](https://github.com/iLioh/azzu-cloud-infra#readme). App code/CI image and OIDC credential are published; server TLS has been issued and merged in private Key Vault. BFF Deployment/Service and gateway are NOT deployed. Banking adapters, ACTIVATION_ONLY, federated logout and real step-up/E2E remain pending. DEV is one replica with no HPA; distributed sessions/Data Protection are not implemented.

This publication changes documentation/diagnostic tools only, not the API implementation or deployed image. All checkpoints below are **historical**, including counts and statements about earlier unconfigured credentials. They must not be used as the current Azure inventory.

## Historical local status — 2026-10-01, readiness review

The BFF is **not complete or deployed**. This review fixed reauthentication session rotation and added
explicit opt-in trusted proxy handling for public OIDC callbacks and suppressed framework request URL logging
in DEV/base configuration. Release build: 0 warnings/errors;
135 tests passed; a fresh local Linux image and SBOM were produced, with 0 HIGH/CRITICAL and 0 secrets
reported by Trivy. Linux runtime smoke is blocked locally (Docker unavailable), and CI/publication,
server TLS/private deployment, same-origin gateway, real login/logout/step-up and Banking integration remain pending.
Azure read-only checks confirmed no BFF Deployment/Service/Ingress, existing ServiceAccount, BFF registration
and CI/CD AcrPush. See `BFF_READINESS_REVIEW_2026-10-01.md` for evidence and acceptance gates.
All sections below retain historical checkpoints; do not treat their older "not implemented" lists as current inventory.

## Latest local update — 2026-10-01, delegated Banking tokens

The disabled-by-default delegated access-token acquisition/refresh path, protected DEV server-side
token storage and Infrastructure transport are now implemented. Release build: 0 errors/warnings;
125 BFF tests and 43 Angular tests passed. See `DELEGATED_BANKING_TOKENS_2026-10-01.md` for the exact
scope, activation prerequisites and limitations. API audience/scopes/consent and Sara's typed contract
are still pending; no Azure changes, publication or real login/API integration in this update.
The sections below include older baseline results and must not be interpreted as live Azure inventory.

## Implemented and validated locally

- .NET 8 solution with API, Application, Domain, Infrastructure and Contracts projects.
- Web BFF route skeleton matching the validated Angular contract.
- Cookie/OIDC boundary, CSRF filter, correlation middleware, security headers, rate limiting, idempotency-key validation and RFC 9457 error handling through `IProblemDetailsService`.
- Explicit Entra `(provider, iss, OID/oid, tid) -> customerId` Mapping port and HTTP/mTLS adapter, disabled by default, with distinct 401/403/503 outcomes.
- Authentication Context claims challenge skeleton for Entra External ID step-up; real-tenant validation remains pending.
- Session expiration is read from the authenticated ticket, and the session cookie is `__Host-AzzuSession`.
- Ports for Banking Services and customer security remain deliberately unavailable; Mapping is independently configurable.
- `/auth/status`, safe portal return after login/step-up, `/api/v1/auth/callback`, generic OIDC failure UX, and local logout with CSRF/cookie cleanup.
- Development-only opaque server-side ticket store; bounded and absolute-expiring, not distributed or persistent.
- Secure multi-stage Dockerfile using the built-in non-root ASP.NET container user.
- Tests for health, OIDC configuration, ticket expiry, session cleanup, identity mapping outcomes, CSRF, Problem Details, idempotency-key enforcement and step-up challenge construction.

Validation run:

~~~text
dotnet build Azzu.WebBff.sln -c Release
Result: 0 warnings, 0 errors

dotnet test Azzu.WebBff.sln -c Release --no-restore
Result: 73 passed, 0 failed (2026-10-01; includes real cookie/session integration tests)
~~~

## Intentionally not implemented

- Entra External ID app registration and runtime secret configuration.
- Distributed server-side token/session store and shared Data Protection keys.
- Live Mapping connection, Banking Services adapters, durable idempotency, and direct core/database access (prohibited for the BFF).
- Azure resources, Kubernetes manifests, Front Door, APIM, Key Vault bindings, DNS and CI deployment.
- Any change to Mobile or apimovil.azzu.tech.

The API blocks production startup until the session/token store and Data Protection strategy are implemented. This is intentional defense-in-depth, not a deployment failure to bypass.

## Next technical gate

Approve the adapter and identity-link contracts, then validate OIDC/Authentication Context against the real External ID tenant before implementing the first read-only Banking Services adapter.
