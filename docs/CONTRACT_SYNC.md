# Web BFF contract ownership

The current Web handoff snapshot lives in this repository:

~~~text
docs/openapi/web-bff.openapi.yaml
~~~

Copied byte-for-byte from Estiven's local Angular contract on 2026-10-02; SHA-256 `0054A3187A1BE390AEC0CFA2A92CB5FAF7121809EC3B0306BCA9AD529C3D4BC0`. It remains a draft: route/schema validation does not imply deployed implementation. Angular source is not pushed by this handoff. Agree a version/tag before consuming subsequent breaking changes. In particular, capability routes (including digital-key changes) are not authorization for Angular/BFF to capture the provider's login credentials.

Rules:

1. Any breaking change requires a new API version.
2. Financial operations need idempotency and domain authorization tests.
3. HTTP 401 is used for unauthenticated/expired sessions and step-up challenges.
4. HTTP 403 with code CSRF_VALIDATION_FAILED is used for CSRF failures.
5. HTTP 428 remains available only for precondition semantics.
6. Problem responses follow RFC 9457 and include X-Correlation-ID.
7. HTTP 401 `BANKING_REAUTHENTICATION_REQUIRED` means the delegated token provider requires interaction; preserve the local session and enter the fixed local login route. Never follow untrusted provider challenge URLs or replay a financial operation. It does not prove MFA/step-up completion.
