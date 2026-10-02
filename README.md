# AZZU Web BFF

Backend for the browser channel of AZZU Banking.

## Scope

This service owns the Web channel boundary only:

- OIDC authorization-code login/callback and local logout; federated logout remains pending.
- Secure HttpOnly session cookie, CSRF/XSRF, step-up challenge and session lifecycle.
- RFC 9457 Problem Details, correlation IDs, validation and channel-specific rate limits.
- Adapters to the shared Banking Services boundary.

It does **not** calculate balances, operate a ledger, approve loans, execute card rules or access PostgreSQL directly. Mapping uses the explicitly approved private Tailscale proxy; this does not permit generic tailnet/Core access.

## Architecture

~~~text
Angular SPA → Front Door/WAF → APIM → Web BFF → Banking Services → Integration/Core → Tailscale → PostgreSQL on-prem
~~~

The BFF has no direct dependency on PostgreSQL. Until the Mobile/Core capability mapping is accepted, the banking adapter is intentionally unavailable rather than returning fabricated financial data.

## Local prerequisites

- .NET SDK 8.0.425 or later patch in the 8.0 line.
- No cloud secret is required for build or unit tests.
- OIDC settings are supplied only through a secure runtime configuration source in deployed environments.

## Commands

~~~powershell
& "C:\Program Files\dotnet\dotnet.exe" restore
& "C:\Program Files\dotnet\dotnet.exe" build --no-restore
& "C:\Program Files\dotnet\dotnet.exe" test --no-build
& "C:\Program Files\dotnet\dotnet.exe" run --project src/Azzu.WebBff.Api
~~~

The API refuses to pretend that OIDC or core-banking adapters are configured. Health endpoints are unauthenticated; banking endpoints require authentication and return RFC 9457 errors until their approved adapter exists.

## Repositories

- Frontend: azzu-banking-web
- This service: azzu-web-bff
- Infrastructure: [azzu-cloud-infra](https://github.com/iLioh/azzu-cloud-infra), already published; authoritative handoff and Kubernetes templates live there.

## Handoff to Aldo — 2026-10-02

Read the [single authoritative handoff](https://github.com/iLioh/azzu-cloud-infra#readme) before interpreting dated reports. App code and the verified ACR image were already published; this follow-up publishes documentation, a Web contract snapshot and diagnostic/PKI source only. No Angular changes or Azure deployment are included.

- [Web BFF OpenAPI snapshot](docs/openapi/web-bff.openapi.yaml), copied exactly from Estiven's current local Angular contract. It remains `1.0.0-draft`, not proof that all banking routes work. Origin SHA-256: `0054A3187A1BE390AEC0CFA2A92CB5FAF7121809EC3B0306BCA9AD529C3D4BC0`.
- [Implementation status](docs/IMPLEMENTATION_STATUS.md), [Mapping adapter](docs/IDENTITY_MAPPING_DESIGN.md), [delegated tokens](docs/DELEGATED_BANKING_TOKENS_2026-10-01.md) and [security baseline](docs/SECURITY_BASELINE.md).
- `tools/Azzu.MappingProbe` / `tools/Azzu.OidcProbe` are DEV diagnostics, **not a deployed BFF or login E2E**. Mapping fixtures are supplied explicitly, never hardcoded customer identities. Build their projects separately; they are not in the main solution.
- [PKI tools and limitations](scripts/pki/README.md): source only, no private keys/state/PKI bundles included. Do not rerun completed issuance blindly.
- `scripts/Test-OidcLoginPreflight.ps1` reads metadata/discovery only. It does not demonstrate successful user login.

No workflows were modified. This handoff commit uses `[skip ci]` so existing push-triggered pipelines do not publish a replacement image or attempt CD. The previously verified image digest in the infra README remains the deployment candidate. Later application changes must pass normal CI; this is not permission to bypass release gates.

Local publication checks: Release build and 152 BFF tests passed; both diagnostic projects built with 0 warnings/errors; 33 offline PKI cases passed (including the available public-chain fixture); 13 PowerShell scripts parsed; OpenAPI 3.1 formal schema and 22 unique operation IDs validated. Selected source scan found no secrets or the known customer fixture IDs. These checks are not Azure runtime/login E2E validation. Earlier raw audit reports remain local; no private keys, operator account state or actual customer fixtures are needed to clone/build.

Estiven retains frontend ownership. Deployment/Service, private DNS, gateway, actual OIDC/logout/step-up, ACTIVATION_ONLY, and Banking API integration are still pending as documented. No secret-sharing or new broad permissions are required for cloning these public repos.

