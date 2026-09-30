using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Azzu.WebBff.Api.Configuration;
using Azzu.WebBff.Api.Security;
using Azzu.WebBff.Application;
using Azzu.WebBff.Domain;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace Azzu.WebBff.Api.Tests;

public sealed class WebBffSmokeTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string TestScheme = "Test";
    private readonly WebApplicationFactory<Program> _factory;

    public WebBffSmokeTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("environment", "Development");
            builder.ConfigureTestServices(services =>
            {
                services.AddAuthentication(TestScheme)
                    .AddScheme<AuthenticationSchemeOptions, TestAuthenticationHandler>(TestScheme, _ => { });
                services.PostConfigure<AuthenticationOptions>(options =>
                {
                    options.DefaultAuthenticateScheme = TestScheme;
                    options.DefaultChallengeScheme = TestScheme;
                });
                services.PostConfigure<AuthorizationOptions>(options =>
                {
                    options.FallbackPolicy = new AuthorizationPolicyBuilder(TestScheme)
                        .RequireAuthenticatedUser()
                        .Build();
                });
                services.RemoveAll<ICustomerIdentityMapping>();
                services.AddSingleton<ICustomerIdentityMapping, TestCustomerIdentityMapping>();
            });
        });
    }

    [Fact]
    public async Task LiveHealthReturnsSuccessAndCorrelationId()
    {
        using var client = _factory.CreateClient();
        using var response = await client.GetAsync("/health/live");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.Contains("X-Correlation-ID"));
        Assert.True(response.Headers.Contains("X-Content-Type-Options"));
    }

    [Fact]
    public async Task LoginDoesNotFakeOidcFlowWhenConfigurationIsMissing()
    {
        using var client = _factory.CreateClient();
        using var response = await client.GetAsync("/api/v1/auth/login");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("OIDC_NOT_CONFIGURED", (await ReadProblemAsync(response)).Code);
    }

    [Fact]
    public async Task SessionUsesAuthenticationTicketExpiry()
    {
        using var client = CreateAuthenticatedClient();
        using var response = await client.GetAsync("/api/v1/auth/session");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var session = await response.Content.ReadFromJsonAsync<SessionPayload>();
        Assert.NotNull(session);
        Assert.InRange(session.ExpiresAtUtc, DateTimeOffset.UtcNow.AddMinutes(9), DateTimeOffset.UtcNow.AddMinutes(11));
    }

    [Fact]
    public async Task ExpiredSessionReturns401AndClearsSessionCookie()
    {
        using var client = CreateAuthenticatedClient("linked", expired: true);
        using var response = await client.GetAsync("/api/v1/auth/session");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("INVALID_SESSION_CONTEXT", (await ReadProblemAsync(response)).Code);
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), value =>
            value.StartsWith(AuthenticationExtensions.SessionCookieName + "=", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ValidIdentityWithoutBankingLinkReturns403WithoutDestroyingSession()
    {
        using var client = CreateAuthenticatedClient("unlinked");
        using var response = await client.GetAsync("/api/v1/accounts");

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("CUSTOMER_IDENTITY_NOT_LINKED", (await ReadProblemAsync(response)).Code);
        Assert.False(response.Headers.TryGetValues("Set-Cookie", out _));
    }

    [Fact]
    public async Task MappingOutageReturns503WithoutDestroyingSession()
    {
        using var client = CreateAuthenticatedClient("mapping-unavailable");
        using var response = await client.GetAsync("/api/v1/accounts");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("CUSTOMER_IDENTITY_MAPPING_UNAVAILABLE", (await ReadProblemAsync(response)).Code);
        Assert.False(response.Headers.TryGetValues("Set-Cookie", out _));
    }

    [Fact]
    public async Task MissingIssuerOrSubjectIsControlled401ProblemDetails()
    {
        using var client = CreateAuthenticatedClient("omit");
        using var response = await client.GetAsync("/api/v1/accounts");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("INVALID_SESSION_CONTEXT", (await ReadProblemAsync(response)).Code);
    }

    [Fact]
    public async Task UnsafeRequestWithoutCsrfTokenReturns403ProblemDetails()
    {
        using var client = CreateAuthenticatedClient();
        using var response = await client.PostAsync("/api/v1/notifications/read", null);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("CSRF_VALIDATION_FAILED", (await ReadProblemAsync(response)).Code);
    }

    [Fact]
    public async Task SensitiveWriteWithoutIdempotencyKeyReturns400AfterCsrfValidation()
    {
        using var client = CreateAuthenticatedClient();
        await AttachCsrfTokenAsync(client);

        using var response = await client.PostAsJsonAsync("/api/v1/transfers", new
        {
            sourceAccountId = Guid.NewGuid(),
            recipientDocument = "12345678",
            recipientName = "Cliente Prueba",
            amount = 10.50m,
            description = "Prueba"
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("IDEMPOTENCY_KEY_REQUIRED", (await ReadProblemAsync(response)).Code);
    }

    [Fact]
    public async Task ValidIdempotencyKeyPassesEdgeValidationToBankingPort()
    {
        using var client = CreateAuthenticatedClient();
        await AttachCsrfTokenAsync(client);
        client.DefaultRequestHeaders.Add(IdempotencyKeyFilter.HeaderName, Guid.NewGuid().ToString("D"));

        using var response = await client.PostAsJsonAsync("/api/v1/transfers", new
        {
            sourceAccountId = Guid.NewGuid(),
            recipientDocument = "12345678",
            recipientName = "Cliente Prueba",
            amount = 10.50m,
            description = "Prueba"
        });

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("BANKING_DEPENDENCY_UNAVAILABLE", (await ReadProblemAsync(response)).Code);
    }

    [Fact]
    public async Task StepUpRequiresAuthenticationAndDoesNotClearAnExistingSession()
    {
        using var anonymous = _factory.CreateClient();
        using var unauthorized = await anonymous.GetAsync("/api/v1/auth/step-up");
        Assert.Equal(HttpStatusCode.Unauthorized, unauthorized.StatusCode);

        using var authenticated = CreateAuthenticatedClient();
        using var unavailable = await authenticated.GetAsync("/api/v1/auth/step-up");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, unavailable.StatusCode);
        Assert.False(unavailable.Headers.TryGetValues("Set-Cookie", out _));
    }

    [Fact]
    public void StepUpChallengeUsesOidcClaimsParameterAndRoundTripsRequiredContext()
    {
        var options = Options.Create(new StepUpOptions
        {
            AuthenticationContexts = new Dictionary<string, string>
            {
                ["transfers.create"] = "c1"
            }
        });
        var factory = new StepUpChallengeFactory(options);

        var properties = factory.Create("transfers.create", "/api/v1/auth/session");

        var claims = Assert.IsType<string>(properties.Parameters[StepUpChallengeFactory.ClaimsParameter]);
        Assert.Contains("\"acrs\"", claims, StringComparison.Ordinal);
        Assert.Contains("\"c1\"", claims, StringComparison.Ordinal);
        Assert.Equal("c1", properties.Items[StepUpChallengeFactory.RequiredAuthenticationContextItem]);
        Assert.False(properties.Parameters.ContainsKey("acr_values"));

        var satisfiedPrincipal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("acrs", "c1")], "Test"));
        var insufficientPrincipal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("acrs", "c2")], "Test"));
        Assert.True(StepUpChallengeFactory.HasRequiredContext(properties, satisfiedPrincipal));
        Assert.False(StepUpChallengeFactory.HasRequiredContext(properties, insufficientPrincipal));
    }

    private HttpClient CreateAuthenticatedClient(string subject = "linked", bool expired = false)
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            HandleCookies = true
        });
        client.DefaultRequestHeaders.Add(TestAuthenticationHandler.SubjectHeader, subject);
        if (expired)
        {
            client.DefaultRequestHeaders.Add(TestAuthenticationHandler.ExpiredHeader, "true");
        }

        return client;
    }

    private static async Task AttachCsrfTokenAsync(HttpClient client)
    {
        using var response = await client.GetAsync("/api/v1/auth/session");
        response.EnsureSuccessStatusCode();
        var setCookie = response.Headers.GetValues("Set-Cookie")
            .Single(value => value.StartsWith("XSRF-TOKEN=", StringComparison.Ordinal));
        var encodedToken = setCookie.Split(';', 2)[0]["XSRF-TOKEN=".Length..];
        client.DefaultRequestHeaders.Add("X-XSRF-TOKEN", Uri.UnescapeDataString(encodedToken));
    }

    private static async Task<ProblemPayload> ReadProblemAsync(HttpResponseMessage response) =>
        await response.Content.ReadFromJsonAsync<ProblemPayload>()
        ?? throw new InvalidOperationException("A Problem Details response was expected.");

    private sealed record ProblemPayload(string Code);
    private sealed record SessionPayload(DateTimeOffset ExpiresAtUtc);

    private sealed class TestCustomerIdentityMapping : ICustomerIdentityMapping
    {
        public Task<string?> ResolveCustomerIdAsync(
            ExternalIdentity identity,
            CancellationToken cancellationToken) =>
            identity.Subject switch
            {
                "linked" => Task.FromResult<string?>("customer-123"),
                "unlinked" => Task.FromResult<string?>(null),
                "mapping-unavailable" => throw new CustomerIdentityMappingUnavailableException("Mapping unavailable."),
                _ => Task.FromResult<string?>(null)
            };
    }

    private sealed class TestAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        public const string SubjectHeader = "X-Test-Subject";
        public const string ExpiredHeader = "X-Test-Expired";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue(SubjectHeader, out var subjectValues))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var subject = subjectValues.ToString();
            var claims = new List<Claim>
            {
                new("iss", "https://issuer.example.test"),
                new("name", "Mariana"),
                new("sid", "test-session")
            };
            if (!string.Equals(subject, "omit", StringComparison.Ordinal))
            {
                claims.Add(new Claim("sub", subject));
            }

            var identity = new ClaimsIdentity(claims, Scheme.Name, "name", ClaimTypes.Role);
            var properties = new AuthenticationProperties
            {
                IssuedUtc = DateTimeOffset.UtcNow.AddMinutes(-1),
                ExpiresUtc = Request.Headers.ContainsKey(ExpiredHeader)
                    ? DateTimeOffset.UtcNow.AddMinutes(-1)
                    : DateTimeOffset.UtcNow.AddMinutes(10)
            };

            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(identity), properties, Scheme.Name)));
        }
    }
}
