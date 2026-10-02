using System.Threading.RateLimiting;
using Azzu.WebBff.Api.Endpoints;
using Azzu.WebBff.Api.Security;
using Azzu.WebBff.Application;
using Azzu.WebBff.Infrastructure;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAzzuTrustedProxy(builder.Configuration);

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

var oidcRuntimeOptions = builder.Configuration.GetSection("Oidc").Get<Azzu.WebBff.Api.Configuration.OidcOptions>() ?? new();
if (oidcRuntimeOptions.CredentialMode == "Certificate" && !oidcRuntimeOptions.IsConfigured)
    throw new InvalidOperationException("OIDC certificate mode configuration is incomplete.");
using var oidcRuntimeCertificate = oidcRuntimeOptions.CredentialMode == "Certificate"
    ? await KeyVaultOidcCertificateLoader.FromWorkloadIdentity(oidcRuntimeOptions.Certificate).LoadAsync(oidcRuntimeOptions.Certificate, CancellationToken.None)
    : null;
builder.Services.AddAzzuAuthentication(builder.Configuration, oidcRuntimeCertificate);
var bankingTokenOptions = builder.Configuration.GetSection("BankingTokens").Get<Azzu.WebBff.Api.Configuration.BankingTokenOptions>() ?? new();
if (bankingTokenOptions.Enabled && !builder.Environment.IsDevelopment())
    throw new InvalidOperationException("Delegated tokens currently require the single-replica Development server-side store. Distributed store must be implemented before enabling other environments.");
builder.Services.AddHttpContextAccessor();
builder.Services.AddSingleton<IOidcRefreshCredential>(new OidcRefreshCredential(oidcRuntimeOptions, oidcRuntimeCertificate));
builder.Services.AddScoped<IBankingAccessTokenProvider, DelegatedBankingTokens>();
builder.Services.AddSingleton(new BankingApiTransportOptions(bankingTokenOptions.Enabled, bankingTokenOptions.BaseUrl));
builder.Services.AddHttpClient("oidc-token-refresh", client =>
    {
        client.Timeout = TimeSpan.FromSeconds(bankingTokenOptions.TimeoutSeconds);
        client.MaxResponseContentBufferSize = 64 * 1024;
    })
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false })
    .RemoveAllLoggers();
builder.Services.AddHttpClient<DelegatedBankingClient>(client => client.Timeout = TimeSpan.FromSeconds(bankingTokenOptions.TimeoutSeconds))
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false })
    .RemoveAllLoggers();
if (builder.Environment.IsDevelopment())
{
    builder.Services.AddSingleton<DevelopmentTicketStore>();
    builder.Services.AddSingleton<IServerSideTokenSessionStore>(services => services.GetRequiredService<DevelopmentTicketStore>());
    builder.Services.AddOptions<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions>(AuthenticationExtensions.CookieScheme)
        .Configure<DevelopmentTicketStore>((options, store) => options.SessionStore = store);
    builder.Services.AddOptions<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions>(AuthenticationExtensions.SessionIssuerScheme)
        .Configure<DevelopmentTicketStore>((options, store) => options.SessionStore = store);
}
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
var mappingOptions = builder.Configuration.GetSection("IdentityMapping").Get<IdentityMappingOptions>() ?? new();
builder.Services.AddSingleton(mappingOptions);
if (mappingOptions.Enabled)
{
    mappingOptions.Validate();
    if (!builder.Environment.IsDevelopment() && mappingOptions.DisableRevocationCheckForDevelopment)
    {
        throw new InvalidOperationException("Mapping certificate revocation checks can only be disabled in Development.");
    }
    if (!builder.Environment.IsDevelopment() && mappingOptions.CertificateSource != "KeyVault")
    {
        throw new InvalidOperationException("Mapping must use the Key Vault certificate source outside Development.");
    }
}
using var mappingRuntimeCertificate = mappingOptions.Enabled && mappingOptions.CertificateSource == "KeyVault"
    ? await KeyVaultMappingCertificateLoader.FromWorkloadIdentity(mappingOptions).LoadAsync(mappingOptions, CancellationToken.None)
    : null;
if (mappingOptions.Enabled)
{
    builder.Services.AddHttpClient<ICustomerIdentityMapping, HttpCustomerIdentityMapping>(client =>
    {
        client.BaseAddress = new Uri(mappingOptions.Endpoint);
        client.Timeout = Timeout.InfiniteTimeSpan;
    }).ConfigurePrimaryHttpMessageHandler(() => IdentityMappingTransport.Create(mappingOptions, mappingRuntimeCertificate))
        .RemoveAllLoggers();
}
else
{
    builder.Services.AddSingleton<ICustomerIdentityMapping, UnavailableCustomerIdentityMapping>();
}
builder.Services.AddSingleton<IProductionSessionSecurityReadiness, UnconfiguredProductionSessionSecurityReadiness>();
builder.Services.AddScoped<CustomerOperationContextFactory>();
builder.Services.AddSingleton<StepUpChallengeFactory>();

var app = builder.Build();

app.Environment.ValidateProductionSessionConfiguration(
    app.Services.GetRequiredService<IProductionSessionSecurityReadiness>());

if (builder.Configuration.GetValue<bool>("Gateway:ForwardedHeadersEnabled")) app.UseForwardedHeaders();
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
