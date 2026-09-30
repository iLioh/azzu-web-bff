namespace Azzu.WebBff.Api.Security;

public sealed class IdempotencyKeyFilter : IEndpointFilter
{
    // This channel-edge filter validates and forwards the key only. Durable deduplication,
    // response replay and atomic operation storage belong to Banking Services/Core.
    public const string HeaderName = "Idempotency-Key";

    public ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var key = context.HttpContext.Request.Headers[HeaderName].FirstOrDefault();

        if (!Guid.TryParse(key, out _))
        {
            return ValueTask.FromResult<object?>(Results.Problem(
                statusCode: StatusCodes.Status400BadRequest,
                title: "A valid idempotency key is required",
                type: "https://azzu.tech/problems/idempotency-key-required",
                extensions: new Dictionary<string, object?>
                {
                    ["code"] = "IDEMPOTENCY_KEY_REQUIRED",
                    [CorrelationIdMiddleware.HeaderName] = CorrelationIdMiddleware.GetCorrelationId(context.HttpContext)
                }));
        }

        context.HttpContext.Items[HeaderName] = key;
        return next(context);
    }
}
