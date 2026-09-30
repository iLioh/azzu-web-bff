# Identity mapping: issuer + subject to customerId

## Invariant

The external identity key is the exact pair `(issuer, subject)` from validated OIDC claims. `subject` is never a fallback for `customerId`, and email, document number or display name are not stable identity keys.

~~~text
validated Entra token/session
        |
        | iss + sub
        v
ICustomerIdentityMapping
        |
        v
Banking identity-link capability
        |
        v
immutable customerId
~~~

The authoritative mapping belongs behind Banking Services/Customer Profile, not in an Angular claim and not in BFF-local configuration. Its data model must enforce a unique normalized `(issuer, subject)` key, reference an immutable `customerId`, retain lifecycle status and audit link/unlink operations.

## Outcomes

| Condition | HTTP | Code | Session |
|---|---:|---|---|
| Session absent/expired, or validated principal lacks `iss`/`sub` | 401 | `INVALID_SESSION_CONTEXT` | Clear cookie |
| Valid external identity has no customer link | 403 | `CUSTOMER_IDENTITY_NOT_LINKED` | Preserve |
| Mapping capability is unavailable | 503 | `CUSTOMER_IDENTITY_MAPPING_UNAVAILABLE` | Preserve |
| Link exists | continue | n/a | Preserve |

Short-lived positive caching may be evaluated later, but revocation, unlinking, tenant boundaries and stale authorization risk must be addressed first. Negative mappings should not be cached broadly. Mapping failures must not silently fall back to a claim.

The current `UnavailableCustomerIdentityMapping` is deliberate fail-closed behavior until the approved adapter exists.
