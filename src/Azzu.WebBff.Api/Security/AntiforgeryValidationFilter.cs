using Microsoft.AspNetCore.Antiforgery;

namespace Azzu.WebBff.Api.Security;

public sealed class AntiforgeryValidationFilter(IAntiforgery antiforgery) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var request = context.HttpContext.Request;
        if (HttpMethods.IsGet(request.Method) ||
            HttpMethods.IsHead(request.Method) ||
            HttpMethods.IsOptions(request.Method))
        {
            return await next(context);
        }

        try
        {
            await antiforgery.ValidateRequestAsync(context.HttpContext);
        }
        catch (AntiforgeryValidationException)
        {
            return Results.Problem(
                statusCode: StatusCodes.Status403Forbidden,
                title: "CSRF validation failed",
                type: "https://azzu.tech/problems/csrf-validation-failed",
                extensions: new Dictionary<string, object?>
                {
                    ["code"] = "CSRF_VALIDATION_FAILED",
                    [CorrelationIdMiddleware.HeaderName] = CorrelationIdMiddleware.GetCorrelationId(context.HttpContext)
                });
        }

        return await next(context);
    }
}

