# Step-up design for Microsoft Entra External ID

## Protocol design

Sensitive banking operations map to a tenant-configured Conditional Access Authentication Context ID. The mapping is configuration/policy data, not a hard-coded assumption that `mfa` is always sufficient.

1. Banking policy raises `StepUpRequiredException(operation, detail)`.
2. The BFF returns `401 STEP_UP_REQUIRED` and an authenticated step-up URL in `WWW-Authenticate`.
3. `/api/v1/auth/step-up?operation=...` requires the existing BFF session.
4. `StepUpChallengeFactory` resolves the allow-listed operation to its Authentication Context ID.
5. The OIDC authorization request uses `AuthenticationProperties.Parameters["claims"]` with an essential `id_token.acrs` claim containing that context ID.
6. ASP.NET Core protects state/nonce. The required context ID is retained in `AuthenticationProperties.Items` only as protected round-trip state, not as an outbound protocol parameter.
7. `OnTokenValidated` requires the returned `acrs` claim to contain the requested context before refreshing the BFF session.
8. The existing session is not deleted before the challenge; a cancelled/failed step-up must not be mistaken for ordinary logout.

No `acr_values="mfa"` shortcut is used. Each operation-to-context mapping must be configured only after the matching Conditional Access policy exists in the real External ID tenant.

## Validation gate

Before enabling any sensitive operation:

- validate discovery, callback, claims challenge and `acrs` emission against the real External ID tenant;
- prove that a satisfied context avoids needless prompts and an unsatisfied context invokes the intended control;
- test cancel, timeout, replay, session rotation and concurrent-tab behavior;
- confirm tenant licensing and Conditional Access availability;
- verify that the downstream service rechecks the step-up context and object authorization rather than trusting Angular.

Current configuration intentionally has no Authentication Context IDs. No Entra or Azure setting was changed.
