using System.Security.Claims;
using Azzu.WebBff.Application;
using Azzu.WebBff.Domain;

namespace Azzu.WebBff.Api.Security;

public sealed class CustomerOperationContextFactory(ICustomerIdentityMapping identityMapping)
{
    public async Task<CustomerOperationContext> CreateAsync(
        HttpContext httpContext,
        CancellationToken cancellationToken)
    {
        if (httpContext.User.Identity?.IsAuthenticated != true)
        {
            throw new InvalidSessionContextException("The web session is not authenticated.");
        }

        var issuer = httpContext.User.FindFirstValue("iss");
        var subject = httpContext.User.FindFirstValue("sub");
        var objectId = httpContext.User.FindFirstValue("oid");
        var tenantId = httpContext.User.FindFirstValue("tid");

        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(subject)
            || !Guid.TryParse(objectId, out var oid) || oid == Guid.Empty
            || !Guid.TryParse(tenantId, out var tenant) || tenant == Guid.Empty)
        {
            throw new InvalidSessionContextException(
                "The authenticated session does not contain a valid issuer, session subject and Entra object/tenant identity.");
        }

        var customerId = await identityMapping.ResolveCustomerIdAsync(
            new ExternalIdentity("ENTRA_EXTERNAL_ID", issuer, "OID", objectId!, tenantId),
            cancellationToken);

        if (string.IsNullOrWhiteSpace(customerId))
        {
            throw new CustomerIdentityNotLinkedException(
                "The authenticated identity is not linked to a banking customer.");
        }

        return new CustomerOperationContext(
            customerId,
            subject,
            CustomerOperationContext.WebChannel,
            CorrelationIdMiddleware.GetCorrelationId(httpContext),
            httpContext.User.FindFirstValue("sid"),
            GetStepUpLevel(httpContext.User),
            httpContext.Items.TryGetValue(IdempotencyKeyFilter.HeaderName, out var key) ? key as string : null);
    }

    public static string GetDisplayName(HttpContext httpContext) =>
        httpContext.User.FindFirstValue("name")
        ?? httpContext.User.Identity?.Name
        ?? "Cliente AZZU";

    private static string? GetStepUpLevel(ClaimsPrincipal principal) =>
        principal.FindAll("acrs").Select(claim => claim.Value).FirstOrDefault()
        ?? principal.FindFirstValue("acr");
}
