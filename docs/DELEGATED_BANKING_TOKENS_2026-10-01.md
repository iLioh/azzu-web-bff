# Delegated Banking API access — local implementation, 2026-10-01

> Historical implementation checkpoint. By 2026-10-02 this code is published in the BFF and the verified CI image. Audience/scopes/consent, typed Banking operations and real E2E remain pending; disabled-by-default behavior is unchanged. Use the infra README for current resource/image state, not the historical publication statements below.

## Status and boundaries

Implemented locally, **disabled by default**. No Azure, Entra, AKS, Mobile, DB, Tailscale,
DNS, consent or shared resources were modified. No commits/pushes/deployments performed.
This is not proof of a live federated login or successful Banking API call.

The Entra BFF application Client ID is `cecb6910-e653-4129-8376-c044209a751e`.
It is NOT Banking API's audience and is NOT the runtime Managed Identity Client ID.
Banking API audience/App ID URI/scopes/endpoint remain deliberately blank pending coordination.

## Flow

```text
Angular -- opaque __Host-AzzuSession --> cookie handler / DEV server ticket store
OIDC Code + PKCE + confidential certificate --> Entra code redemption
  openid + profile + offline_access + explicitly approved Banking API delegated scopes
  access/refresh tokens --> protected server-side ticket (never browser cookie)
Banking adapter --> IBankingAccessTokenProvider --> token for configured resource
  valid access token: reuse
  near expiry: serialize refresh per session, confidential credential, rotate refresh token
  keep original session expiry; no automatic financial replay
Infrastructure DelegatedBankingClient --> HTTPS Banking API, bearer access token only
Banking API --> validate JWT/aud/iss/tid/azp/scp --> its own mTLS Mapping --> ownership
```

The Application port is `IBankingAccessTokenProvider`; the ASP.NET security adapter implements it.
The HTTP transport lives in Infrastructure. No business logic moved into the BFF.
No OBO flow is needed for the current cookie/authorization-code channel: the BFF obtains the
resource token itself. A separate bearer-in/OBO architecture would require another design.

## Implemented controls

- Explicit opt-in, distinct GUID API audience, resource-prefixed scopes, no `.default` or mixed resource scopes.
- HTTPS backend, no credentials/query/fragment in configured URL; base path ends in `/`.
- Token endpoint explicitly trusted; certificate mode retains exact endpoint binding and PS256 assertion.
- `SaveTokens` only when feature enabled; cookie sign-in fails closed without a server-side ticket store.
- DEV ticket payloads protected using ASP.NET Data Protection, bounded to 10,000 entries, absolute expiry.
- Single-process bounded lock stripes serialize refresh and logout, preventing refresh-token races.
- Removed/expired tickets cannot be resurrected by renewal. Reauthentication revokes the preceding local reference.
- Original session expiry is never extended by token refresh.
- Refresh token rotation; missing replacement retains existing token as allowed by OAuth response semantics.
- ID tokens never used as bearer. The delegated login strips saved ID tokens; federated logout with id_token_hint
  is not implemented by this change and must be revisited explicitly if the approved provider requires it.
- Token-response validation, granted-scope checks when returned, fixed timeout, 64 KiB response buffer.
- Redirect following and cookie containers disabled; outgoing HTTP factory logging removed.
- Provider error descriptions/raw claims/tokens never forwarded; dependency exceptions contain generic text.
- Exact HTTPS backend authority/base-path allowlist; reject supplied Authorization/Cookie/X-Customer-Id.
- No automatic 401 retry, redirect traversal or mutation replay; caller retains its original idempotency key.

## Failure semantics

| Condition | Response | Session action |
|---|---|---|
| Missing/expired/revoked local session, no renewable grant, `invalid_grant` | 401 `INVALID_SESSION_CONTEXT` | Revoke ticket and clear cookie |
| `interaction_required`, `login_required`, `consent_required` | 401 `BANKING_REAUTHENTICATION_REQUIRED` | Preserve local session, local interactive login |
| Provider unavailable, timeout, malformed response or missing delegated grant | 503 `BANKING_DEPENDENCY_UNAVAILABLE` | Preserve local session |
| Mapping unlinked/blocked/unavailable | Existing distinct 403/403/503 | Existing behavior unchanged |
| Actual operation requires stronger approved auth context | Existing 401 `STEP_UP_REQUIRED` | Preserve session; existing step-up flow |

Angular recognizes the new interactive-token code without clearing valid session state;
it uses `/login?reason=reauthentication-required`, never a server-supplied external URI.
Neither a scope nor a refreshed token proves MFA. Conditional Access/step-up policies and
real access-token claims must be verified with Platform; provider claims challenges are not blindly relayed.

## Activation prerequisites — do NOT guess values

1. Platform supplies Banking API Client ID (v2 audience), App ID URI and exact delegated scopes.
2. Agree endpoint-to-scope matrix with Sara; permissions/consent/preauthorization for BFF client approved.
3. Sara supplies actual internal HTTPS authority with valid hostname/chain, OpenAPI and stable errors.
4. Review initial real access-token claims on a controlled environment without logging full token/PII.
5. Configure approved values in `BankingTokens` through environment/configuration, not secrets committed to Git.
6. OIDC remains certificate-based in DEV, with explicitly configured `TokenEndpoint`.
7. Set `Enabled=true` only in the approved single-replica Development environment.

`BankingTokens.Audience` records the contract expectation. Access tokens are treated as opaque by
the BFF; **the API performs authoritative cryptographic audience/issuer/client/scope validation**.
Do not mistake configuration validation or a decoded unverified JWT for authorization.

## Remaining work / not asserted complete

- Implement typed banking adapters only after the real routes/schemas and error/auth challenge contract arrive.
- Normalize actual API errors without exposing body/headers/PII, set correlation/trace propagation,
  apply bounded response handling and per-operation scopes in those typed adapters.
- Persist idempotency in Banking API/Core, never this token transport.
- Distributed server-side session/token storage, shared protected Data Protection keys, atomic cross-instance refresh,
  revocation and refresh-lock fencing remain unimplemented. Non-Development token activation is blocked.
- DEV requires 1 replica, HPA disabled. Restart loses sessions; protected in-memory data is not a durable store.
- Live browser login/callback/logout, real refresh/revocation, step-up policy and API fixture tests remain pending.
- Federated logout is not completed by local cookie revocation.
- No DNS/gateway/deployment or callback changes were made.

## Validation

Synthetic unit and ASP.NET integration tests cover refresh, rotation, concurrency, expiry,
revocation, provider failures, scope/URL rejection, no ID-token bearer, no write replay,
opaque real browser cookies, OIDC scope setup, CSRF/session regression and Angular handling.
Final command results are recorded below after execution; synthetic tests do not substitute real-tenant E2E.

Final results (2026-10-01):

| Command/check | Result |
|---|---|
| `dotnet build -c Release --no-restore` | PASS, 0 warnings, 0 errors |
| `dotnet test -c Release --no-restore` | PASS, 125 passed, 0 failed, 0 skipped |
| Angular `npm test -- --watch=false` | PASS, 43 tests / 8 files |
| Angular `npm run build` | PASS, production build |
| `dotnet list package --vulnerable --include-transitive` | No vulnerable packages reported by configured NuGet feed |
| Trivy source secret scan | Exit 0, 0 findings; build/generated artifact directories excluded |
| `git diff --check` in both repos | PASS |

No full SAST or real-tenant E2E was run. The existing image archive predates these source changes;
rebuild, smoke-test and scan the new image before publication. No image was published by this task.

## Exact files introduced by this task

- `src/Azzu.WebBff.Api/Configuration/BankingTokenOptions.cs`
- `src/Azzu.WebBff.Api/Security/IServerSideTokenSessionStore.cs`
- `src/Azzu.WebBff.Api/Security/DelegatedBankingTokens.cs`
- `src/Azzu.WebBff.Application/IBankingAccessTokenProvider.cs`
- `src/Azzu.WebBff.Infrastructure/BankingApiTransportOptions.cs`
- `src/Azzu.WebBff.Infrastructure/DelegatedBankingClient.cs`
- `tests/Azzu.WebBff.Api.Tests/DelegatedBankingTokenTests.cs`
- This document.

Existing files extended: Program, AuthenticationExtensions, DevelopmentTicketStore,
ProblemDetailsExceptionHandler, IdentityContextExceptions, appsettings, AuthenticationFlowTests,
CookieSessionIntegrationTests, CONTRACT_SYNC and ITFORBANKING_ADAPTER_DESIGN.
Angular changes limited to banking HTTP interceptor/spec, SessionService, login reason text and OpenAPI.
Pre-existing uncommitted work was preserved; repo-wide diffs include earlier work, not just this task.

## Primary references

- https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.cookies.iticketstore
- https://learn.microsoft.com/en-us/aspnet/core/security/authentication/social/additional-claims
- https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
- https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens
- https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation
