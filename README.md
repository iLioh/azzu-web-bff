# AZZU Web BFF

Backend for the browser channel of AZZU Banking.

## Scope

This service owns the Web channel boundary only:

- OIDC authorization-code login, callback and logout.
- Secure HttpOnly session cookie, CSRF/XSRF, step-up challenge and session lifecycle.
- RFC 9457 Problem Details, correlation IDs, validation and channel-specific rate limits.
- Adapters to the shared Banking Services boundary.

It does **not** calculate balances, operate a ledger, approve loans, execute card rules, access PostgreSQL directly or connect to Tailscale.

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
- Infrastructure: azzu-cloud-infra (future, Bicep only)

No Azure deployment, AKS manifest or infrastructure resource is created by this repository.

