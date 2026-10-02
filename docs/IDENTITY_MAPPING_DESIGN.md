# Identity Mapping adapter — local implementation, 2026-10-01

> Handoff 2026-10-02: the BFF caller certificate is enrolled/merged and Key Vault Workload Identity loading is implemented. The private bootstrap template enables Mapping using those references. The BFF server is not deployed; standalone mTLS diagnostics do not prove Web login. Sections below retain the original local adapter checkpoint; refer to the infra README for the current inventory. No link creation or ACTIVATION_ONLY implementation is claimed here.

## Invariant

The BFF has an HTTP adapter behind `ICustomerIdentityMapping`, disabled by default
(`IdentityMapping:Enabled=false`). The unavailable port remains the default:
no fake customer, database connection or real Mapping traffic. Azure, Mobile,
PostgreSQL and Tailscale were not changed.

Source contract: `77ALDO77/ItForBanking`,
`Identity/src/Azzu.Identity.Mapping/Program.cs`, read on 2026-10-01. The running
service must still be checked before enabling integration.

Validated Entra `iss`, `tid` and `oid` become the Mapping request. `sub` remains
the subject of the BFF session/operation context, never a fallback for `oid` or
`customerId`. OIDC must validate the token first. The adapter additionally pins
issuer/tenant to explicit configuration and rejects empty/non-UUID object IDs.
Keycloak and Entra subjects are not assumed equal. The BFF accepts only
`ENTRA_EXTERNAL_ID/OID`; upstream `KEYCLOAK/SUB` links remain on-prem.

~~~text
validated Entra token/session
        |
        | iss + tid + oid
        v
ICustomerIdentityMapping
        |
        v
Private on-prem HTTPS/mTLS Mapping Service
        |
        v
immutable customerId
~~~

The authoritative mapping and lifecycle belong to the on-prem implementation,
not Angular or a BFF-local store. Resolving a customer does not authorize account
ownership. No link provisioning, caching, DNI or password handling is introduced.

## Private HTTP contract

POST `/internal/identity/resolve` with exactly five fields:

```json
{
  "provider": "ENTRA_EXTERNAL_ID",
  "issuer": "<exact validated and configured Entra issuer>",
  "subjectType": "OID",
  "subject": "<validated oid UUID>",
  "tenantId": "<validated and configured tenant UUID>"
}
```

200 requires `{"customerId":"<nonempty UUID>","status":"ACTIVE"}`. The UUID is
the existing bank customer identifier, not a new `CUST-*` identifier.

## Outcomes

| Condition | HTTP | Code | Session |
|---|---:|---|---|
| Session absent/expired, missing essential iss/sub/oid/tid or wrong trusted identity | 401 | `INVALID_SESSION_CONTEXT` | Clear cookie |
| Valid external identity has no customer link | 403 | `CUSTOMER_IDENTITY_NOT_LINKED` | Preserve |
| Linked customer/link is blocked | 403 | `CUSTOMER_ACCESS_DENIED` | Preserve |
| Mapping capability is unavailable | 503 | `CUSTOMER_IDENTITY_MAPPING_UNAVAILABLE` | Preserve |
| Link exists | continue | n/a | Preserve |

Mapping caller certificate denial, dependency throttling, rejected constructed
requests, bad JSON/customer IDs, TLS/network failures and timeouts become 503;
they do not log the customer out. Client cancellation propagates. No downstream
payload/identity or underlying network exception is exposed in Problem Details.

## Configuration and transport

All connection/certificate settings default to empty. Enabling requires an
explicit HTTPS origin, exact trusted issuer/tenant, 1–30 second timeout and PEM
paths `ClientCertificatePath`, `ClientKeyPath`, `RootCertificatePath` referring to
runtime-mounted material. No certificates or private keys belong in Git.
Key Vault/Workload Identity mounting is a later deployment step, not deployed here.

Client certificate + custom trusted private CA, strict chain flags and serverAuth
EKU are configured through .NET's `CertificateChainPolicy`. Normal TLS hostname,
validity and chain validation remains active; no permissive validation callback.
See [Microsoft's API reference](https://learn.microsoft.com/en-us/dotnet/api/system.net.security.sslclientauthenticationoptions.certificatechainpolicy?view=net-8.0).
Redirects, cookies, proxy forwarding and AIA downloads are disabled.
Browser Cookie/Authorization is never forwarded.

Default revocation policy is Online. If the private DEV CA has no CRL/OCSP,
`DisableRevocationCheckForDevelopment=true` is an explicit DEV-only exception;
startup rejects it outside Development. A production revocation/rotation policy
must be agreed. Certificate replacement requires restarting/recycling the BFF's
handler; no automatic hot rotation is implemented.

Timeout covers headers and streaming body, capped at 16 KiB. There are no retries,
caches or fallbacks. A shared circuit breaker is not implemented yet; assess it
against observed dependency behavior before enabling traffic. Built-in HttpClient
request loggers are disabled to minimize leakage.

Mapping currently creates its own correlation UUID rather than accepting the
incoming one. Cross-system trace joining requires a coordinated contract change;
it is not complete merely because the BFF has a correlation ID.

## Remaining runtime gates

1. Enroll the dedicated BFF caller and securely deliver its client certificate/key
   and public CA certificate (never the CA private key).
2. Confirm DNS/routing from the eventual BFF pod and server certificate SAN for
   `identity-mapping-onprem.itforbanking-dev.svc.cluster.local:7443`.
3. Confirm actual validated BFF Entra `iss/tid/oid` and an authoritative bank link
   without printing tokens or PII.
4. Configure the exact endpoint, trusted identity and mounted paths; agree any DEV
   revocation exception and test real mTLS/allowlist before enabling.

## Local tests and rollback

```powershell
dotnet build Azzu.WebBff.sln --configuration Release
dotnet test Azzu.WebBff.sln --configuration Release --no-build
```

Synthetic in-memory HTTP tests cover exact contract, malformed/oversized responses,
inactive/invalid IDs, error distinctions, wrong issuer/provider/tenant, timeout,
cancellation, sanitized network errors and no retries. API tests cover missing
oid/tid, cookie clearing only on invalid sessions and preserved sessions on 403/503.
These tests do not prove a real on-prem connection or actual Entra login.

Loopback TLS tests also exercise the actual transport using synthetic certificates:
client certificate presentation succeeds for the expected server/CA; wrong server
hostname and wrong CA are rejected without bypass callbacks. Temporary test files
are deleted after each case. Windows Schannel-compatible client key loading is
included; the AKS Linux runtime still needs its own smoke validation.

Rollback: leave `Enabled=false` to use the unavailable mapping port. Code can be
reverted independently; no cloud/on-prem changes are part of this work.

Verification on 2026-10-01: Release build succeeded with zero errors/warnings;
48 tests passed, zero failures/skips. No commit, push or deployment was performed.
