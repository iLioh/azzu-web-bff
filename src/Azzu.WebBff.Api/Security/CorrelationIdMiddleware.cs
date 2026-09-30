using System.Diagnostics;

namespace Azzu.WebBff.Api.Security;

public sealed class CorrelationIdMiddleware(RequestDelegate next)
{
    public const string HeaderName = "X-Correlation-ID";
    public const string ItemName = "AzzuCorrelationId";

    public async Task Invoke(HttpContext context)
    {
        var correlationId = GetSafeCorrelationId(context.Request.Headers[HeaderName].FirstOrDefault());
        context.Items[ItemName] = correlationId;
        context.Response.Headers[HeaderName] = correlationId;

        using var scope = context.RequestServices
            .GetRequiredService<ILogger<CorrelationIdMiddleware>>()
            .BeginScope(new Dictionary<string, object?> { ["CorrelationId"] = correlationId });

        Activity.Current?.SetTag("azzu.correlation_id", correlationId);
        await next(context);
    }

    public static string GetCorrelationId(HttpContext context) =>
        context.Items.TryGetValue(ItemName, out var value) && value is string correlationId
            ? correlationId
            : string.Empty;

    private static string GetSafeCorrelationId(string? requestedValue) =>
        Guid.TryParse(requestedValue, out var correlationId)
            ? correlationId.ToString("D")
            : Guid.NewGuid().ToString("D");
}

