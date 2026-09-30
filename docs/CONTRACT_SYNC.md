# Web BFF contract ownership

The validated initial HTTP contract currently lives in:

~~~text
../bancocloud-web/docs/openapi/web-bff.openapi.yaml
~~~

Before the first implementation release, the contract must be copied or moved into this repository as the versioned server contract, and the Angular client must consume the same tagged version.

Rules:

1. Any breaking change requires a new API version.
2. Financial operations need idempotency and domain authorization tests.
3. HTTP 401 is used for unauthenticated/expired sessions and step-up challenges.
4. HTTP 403 with code CSRF_VALIDATION_FAILED is used for CSRF failures.
5. HTTP 428 remains available only for precondition semantics.
6. Problem responses follow RFC 9457 and include X-Correlation-ID.

