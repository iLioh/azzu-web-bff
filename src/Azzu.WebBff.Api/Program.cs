using System.Threading.RateLimiting;
using Azzu.WebBff.Api.Endpoints;
using Azzu.WebBff.Api.Security;
using Azzu.WebBff.Application;
using Azzu.WebBff.Infrastructure;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddProblemDetails(options =>
{
    options.CustomizeProblemDetails = context =>
    {
        context.ProblemDetails.Extensions[CorrelationIdMiddleware.HeaderName] =
            CorrelationIdMiddleware.GetCorrelationId(context.HttpContext);
    };
});
builder.Services.AddExceptionHandler<ProblemDetailsExceptionHandler>();

builder.Services.AddAntiforgery(options =>
{
    options.Cookie.Name = "__Host-AzzuAntiforgery";
    options.Cookie.Path = "/";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.HeaderName = "X-XSRF-TOKEN";
});

builder.Services.AddAzzuAuthentication(builder.Configuration);
builder.Services.AddHealthChecks();

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("sensitive", httpContext =>
    {
        var partitionKey = httpContext.User.FindFirst("sub")?.Value
            ?? httpContext.Connection.RemoteIpAddress?.ToString()
            ?? "anonymous";

        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey,
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 0,
                AutoReplenishment = true
            });
    });
    options.OnRejected = static async (context, cancellationToken) =>
    {
        var httpContext = context.HttpContext;
        await Results.Problem(
            statusCode: StatusCodes.Status429TooManyRequests,
            title: "Too many requests",
            type: "https://azzu.tech/problems/rate-limit-exceeded",
            extensions: new Dictionary<string, object?>
            {
                ["code"] = "RATE_LIMIT_EXCEEDED",
                [CorrelationIdMiddleware.HeaderName] = CorrelationIdMiddleware.GetCorrelationId(httpContext)
            }).ExecuteAsync(httpContext);
    };
});

builder.Services.AddSingleton<IBankingOperations, UnavailableBankingOperations>();
builder.Services.AddSingleton<IChannelSecurityOperations, UnavailableChannelSecurityOperations>();
builder.Services.AddSingleton<ICustomerIdentityMapping, UnavailableCustomerIdentityMapping>();
builder.Services.AddSingleton<IProductionSessionSecurityReadiness, UnconfiguredProductionSessionSecurityReadiness>();
builder.Services.AddScoped<CustomerOperationContextFactory>();
builder.Services.AddSingleton<StepUpChallengeFactory>();

var app = builder.Build();

app.Environment.ValidateProductionSessionConfiguration(
    app.Services.GetRequiredService<IProductionSessionSecurityReadiness>());

app.UseExceptionHandler();
app.UseHttpsRedirection();
app.UseMiddleware<CorrelationIdMiddleware>();
app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.MapWebBffEndpoints();

app.Run();

public partial class Program;
