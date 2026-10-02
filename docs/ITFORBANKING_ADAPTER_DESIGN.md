# Adapter design: Web BFF to itforbanking-api

## Decision

`itforbanking-api` remains unchanged for Mobile. The Web BFF will consume only an approved, internal and versioned Banking Services contract. If the existing API is used during transition, the adapter will be an anti-corruption layer; Angular will never call `itforbanking-api` directly and the BFF will never access PostgreSQL.

## Shape

~~~text
Web endpoint
  -> Application port (IBankingOperations / IChannelSecurityOperations)
  -> Infrastructure typed HTTP adapter
  -> internal itforbanking-api/Banking Services endpoint
  -> existing Integration/Core boundary
~~~

The adapter will:

- translate BFF DTOs to the approved internal contract and never expose Mobile-specific payloads to Angular;
- authenticate customer operations with server-held delegated Entra v2 access tokens for the distinct Banking API resource, using approved operation scopes;
- never send `X-Customer-Id` as authority; Banking API independently resolves its validated `iss/tid/oid` through Mapping and enforces ownership;
- propagate channel, correlation/trace context and the original idempotency key as metadata, not authorization;
- keep Workload Identity for Azure resource access separate from user-delegated API authentication;
- apply strict connect/request timeouts, bounded response sizes and cancellation;
- retry only safe reads and explicitly retryable failures; never blindly retry a monetary write;
- propagate the same idempotency key for sensitive writes, while Banking Services/Core owns durable deduplication and atomic response replay;
- normalize downstream errors to the Web BFF Problem Details contract without leaking internals or PII;
- emit dependency telemetry without logging tokens, full account/card data or request bodies.

## Required discovery before implementation

1. Freeze the actual internal routes, schemas, auth mechanism and ownership checks exposed by `itforbanking-api`.
2. Classify every capability as reusable, Mobile-only, missing or unsafe for Web.
3. Start with read-only accounts and transactions.
4. Add contract/integration tests against a non-production instance.
5. Add sensitive writes only after durable idempotency, object authorization and step-up requirements are proven.

The delegated transport and server-side token provider are implemented locally, disabled by default.
The typed `IBankingOperations`/`IChannelSecurityOperations` adapters still await Sara's approved routes,
schemas and errors. No API responses or banking rules are fabricated. See `DELEGATED_BANKING_TOKENS_2026-10-01.md`.
