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
- send the immutable `customerId`, channel, correlation/trace context and idempotency key as trusted service-to-service context;
- authenticate workload-to-workload with Managed/Workload Identity when the target supports it; no user token forwarding by default;
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

No adapter is implemented in this change.
