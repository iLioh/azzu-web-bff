using System.Net;
using System.Security.Claims;
using System.Text;
using Azzu.WebBff.Api.Configuration;
using Azzu.WebBff.Api.Security;
using Azzu.WebBff.Application;
using Azzu.WebBff.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Xunit;

namespace Azzu.WebBff.Api.Tests;

public sealed class DelegatedBankingTokenTests
{
    private const string Scope = "api://11111111-1111-1111-1111-111111111111/Banking.Read";
    private static BankingTokenOptions Configuration => new()
    {
        Enabled = true, Audience = "11111111-1111-1111-1111-111111111111",
        AppIdUri = "api://11111111-1111-1111-1111-111111111111", BaseUrl = "https://banking.example.test/api/", Scopes = [Scope]
    };

    [Fact]
    public void DisabledConfigurationDoesNotRequireInventedAudienceOrScopes() => new BankingTokenOptions().Validate();

    [Theory]
    [InlineData("http://banking.example.test/api/", Scope)]
    [InlineData("https://user:secret@banking.example.test/api/", Scope)]
    [InlineData("https://banking.example.test/api/", "api://other/Banking.Read")]
    [InlineData("https://banking.example.test/api/", "api://11111111-1111-1111-1111-111111111111/.default")]
    public void UnsafeConfigurationIsRejected(string baseUrl, string scope) =>
        Assert.Throws<InvalidOperationException>(() => new BankingTokenOptions
        {
            Enabled = true, Audience = Configuration.Audience, AppIdUri = Configuration.AppIdUri, BaseUrl = baseUrl, Scopes = [scope]
        }.Validate());

    [Fact]
    public async Task ValidAccessTokenIsReusedWithoutContactingProvider()
    {
        using var fixture = await Fixture.CreateAsync(false);
        Assert.Equal("synthetic-access", await fixture.Provider.GetAsync([Scope], default));
        Assert.Equal(0, fixture.Handler.Calls);
    }

    [Fact]
    public async Task ConcurrentRequestsRefreshOnceAndRotateRefreshTokenWithoutExtendingSession()
    {
        using var fixture = await Fixture.CreateAsync(true);
        var before = (await fixture.Store.RetrieveAsync(fixture.Key))!.Properties.ExpiresUtc;
        var values = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => fixture.Provider.GetAsync([Scope], default)));
        Assert.All(values, value => Assert.Equal("synthetic-new-access", value));
        Assert.Equal(1, fixture.Handler.Calls);
        Assert.Contains("grant_type=refresh_token", fixture.Handler.Form);
        Assert.Contains("refresh_token=synthetic-refresh", fixture.Handler.Form);
        Assert.DoesNotContain("id_token", fixture.Handler.Form);
        var after = (await fixture.Store.RetrieveAsync(fixture.Key))!;
        Assert.Equal(before, after.Properties.ExpiresUtc);
        Assert.Equal("synthetic-new-refresh", after.Properties.GetTokenValue("refresh_token"));
    }

    [Fact]
    public async Task RefreshResponseNeverStoresReturnedIdToken()
    {
        using var fixture = await Fixture.CreateAsync(true);
        await fixture.Provider.GetAsync([Scope], default);
        Assert.Null((await fixture.Store.RetrieveAsync(fixture.Key))!.Properties.GetTokenValue("id_token"));
    }

    [Theory]
    [InlineData("invalid_grant")]
    public async Task RevokedRefreshRequiresLoginAndRevokesLocalTicket(string error)
    {
        using var fixture = await Fixture.CreateAsync(true);
        fixture.Handler.Status = HttpStatusCode.BadRequest;
        fixture.Handler.Json = "{\"error\":\"" + error + "\",\"error_description\":\"private-provider-details\"}";
        var exception = await Assert.ThrowsAsync<InvalidSessionContextException>(() => fixture.Provider.GetAsync([Scope], default));
        Assert.DoesNotContain("private-provider-details", exception.ToString());
        Assert.Null(await fixture.Store.RetrieveAsync(fixture.Key));
    }

    [Theory]
    [InlineData("interaction_required")]
    [InlineData("login_required")]
    [InlineData("consent_required")]
    public async Task InteractiveChallengePreservesValidSession(string error)
    {
        using var fixture = await Fixture.CreateAsync(true);
        fixture.Handler.Status = HttpStatusCode.BadRequest;
        fixture.Handler.Json = "{\"error\":\"" + error + "\",\"claims\":\"provider-details-not-forwarded\"}";
        await Assert.ThrowsAsync<BankingReauthenticationRequiredException>(() => fixture.Provider.GetAsync([Scope], default));
        Assert.NotNull(await fixture.Store.RetrieveAsync(fixture.Key));
    }

    [Fact]
    public async Task InteractiveProblemDetailsIs401WithChallengeAndWithoutCookieDeletion()
    {
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(), new AuthenticationProperties(), AuthenticationExtensions.CookieScheme);
        var authentication = new Authentication(ticket);
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddProblemDetails();
        services.AddSingleton<IAuthenticationService>(authentication);
        using var provider = services.BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = provider };
        context.Response.Body = new MemoryStream();
        var handler = new ProblemDetailsExceptionHandler(NullLogger<ProblemDetailsExceptionHandler>.Instance,
            provider.GetRequiredService<IProblemDetailsService>());
        Assert.True(await handler.TryHandleAsync(context, new BankingReauthenticationRequiredException(), default));
        Assert.Equal(401, context.Response.StatusCode);
        Assert.Equal("application/problem+json", context.Response.ContentType);
        Assert.Contains("interaction_required", context.Response.Headers.WWWAuthenticate.ToString());
        Assert.Equal(0, context.Response.Headers.SetCookie.Count);
        Assert.Equal(0, authentication.SignOuts);
        context.Response.Body.Position = 0;
        using var reader = new StreamReader(context.Response.Body);
        Assert.Contains("BANKING_REAUTHENTICATION_REQUIRED", await reader.ReadToEndAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NetworkFailureOrTimeoutReturnsControlledUnavailableAndPreservesSession(bool timeout)
    {
        using var fixture = await Fixture.CreateAsync(true);
        fixture.Handler.Failure = timeout ? new OperationCanceledException("provider-detail") : new HttpRequestException("provider-detail");
        var exception = await Assert.ThrowsAsync<BankingDependencyUnavailableException>(() => fixture.Provider.GetAsync([Scope], default));
        Assert.DoesNotContain("provider-detail", exception.ToString());
        Assert.NotNull(await fixture.Store.RetrieveAsync(fixture.Key));
    }

    [Theory]
    [InlineData("{\"error\":\"temporarily_unavailable\"}", HttpStatusCode.ServiceUnavailable)]
    [InlineData("not-json-private-details", HttpStatusCode.OK)]
    [InlineData("{\"access_token\":\"secret-value\",\"token_type\":\"not-bearer\",\"expires_in\":3600}", HttpStatusCode.OK)]
    [InlineData("{\"access_token\":\"secret-value\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"Other.Scope\"}", HttpStatusCode.OK)]
    public async Task ProviderOutageOrInvalidResponseIsControlledAndPreservesSession(string json, HttpStatusCode status)
    {
        using var fixture = await Fixture.CreateAsync(true);
        fixture.Handler.Json = json;
        fixture.Handler.Status = status;
        var exception = await Assert.ThrowsAsync<BankingDependencyUnavailableException>(() => fixture.Provider.GetAsync([Scope], default));
        Assert.DoesNotContain("secret-value", exception.ToString());
        Assert.DoesNotContain("private-details", exception.ToString());
        Assert.NotNull(await fixture.Store.RetrieveAsync(fixture.Key));
    }

    [Fact]
    public async Task MissingRefreshNeverFallsBackToIdToken()
    {
        using var fixture = await Fixture.CreateAsync(true, false);
        await Assert.ThrowsAsync<InvalidSessionContextException>(() => fixture.Provider.GetAsync([Scope], default));
        Assert.Equal(0, fixture.Handler.Calls);
    }

    [Fact]
    public async Task RevokedSessionCannotRefreshOrBeResurrectedByRenew()
    {
        using var fixture = await Fixture.CreateAsync(true);
        var ticket = (await fixture.Store.RetrieveAsync(fixture.Key))!;
        await fixture.Store.RemoveAsync(fixture.Key);
        await fixture.Store.RenewAsync(fixture.Key, ticket);
        await Assert.ThrowsAsync<InvalidSessionContextException>(() => fixture.Provider.GetAsync([Scope], default));
        Assert.Equal(0, fixture.Handler.Calls);
    }

    [Fact]
    public async Task ScopeNotConfiguredCannotTriggerProviderCall()
    {
        using var fixture = await Fixture.CreateAsync(true);
        await Assert.ThrowsAsync<BankingDependencyUnavailableException>(() => fixture.Provider.GetAsync(["Banking.Write"], default));
        Assert.Equal(0, fixture.Handler.Calls);
    }

    [Theory]
    [InlineData("https://evil.example.test/api/accounts")]
    [InlineData("http://banking.example.test/api/accounts")]
    [InlineData("https://banking.example.test/other/accounts")]
    [InlineData("https://banking.example.test/api/../other")]
    public async Task TransportCannotSendBearerOutsideConfiguredBackend(string destination)
    {
        using var fixture = await Fixture.CreateAsync(false);
        using var http = new HttpClient(fixture.Handler);
        var client = new DelegatedBankingClient(http, fixture.Provider, new(true, Configuration.BaseUrl));
        using var request = new HttpRequestMessage(HttpMethod.Get, destination);
        await Assert.ThrowsAsync<BankingDependencyUnavailableException>(() => client.SendAsync(request, [Scope], default));
        Assert.Equal(0, fixture.Handler.Calls);
    }

    [Theory]
    [InlineData("X-Customer-Id", "attacker-customer")]
    [InlineData("Cookie", "session-from-browser")]
    [InlineData("Authorization", "Bearer id-token-from-browser")]
    public async Task TransportRejectsBrowserCredentialsAndCustomerAuthority(string header, string value)
    {
        using var fixture = await Fixture.CreateAsync(false);
        using var http = new HttpClient(fixture.Handler);
        var client = new DelegatedBankingClient(http, fixture.Provider, new(true, Configuration.BaseUrl));
        using var request = new HttpRequestMessage(HttpMethod.Get, "accounts");
        request.Headers.Add(header, value);
        await Assert.ThrowsAsync<BankingDependencyUnavailableException>(() => client.SendAsync(request, [Scope], default));
        Assert.Equal(0, fixture.Handler.Calls);
    }

    [Fact]
    public async Task TransportUsesServerAccessTokenAndDoesNotReplayUnauthorizedMutation()
    {
        using var fixture = await Fixture.CreateAsync(false);
        fixture.Handler.Status = HttpStatusCode.Unauthorized;
        using var http = new HttpClient(fixture.Handler);
        var client = new DelegatedBankingClient(http, fixture.Provider, new(true, Configuration.BaseUrl));
        using var request = new HttpRequestMessage(HttpMethod.Post, "transfers");
        request.Headers.Add("Idempotency-Key", Guid.NewGuid().ToString());
        using var response = await client.SendAsync(request, [Scope], default);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Bearer synthetic-access", fixture.Handler.Authorization);
        Assert.Null(request.Headers.Authorization);
        Assert.Equal(1, fixture.Handler.Calls);
    }

    private sealed class Fixture : IDisposable
    {
        public DevelopmentTicketStore Store { get; } = new();
        public string Key { get; private set; } = "";
        public Handler Handler { get; } = new();
        public DelegatedBankingTokens Provider { get; private set; } = null!;
        private ServiceProvider _services = null!;
        private HttpClient _http = null!;

        public static async Task<Fixture> CreateAsync(bool expired, bool includeRefresh = true)
        {
            var result = new Fixture();
            var properties = new AuthenticationProperties { ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10) };
            properties.StoreTokens([
                new() { Name = "access_token", Value = "synthetic-access" },
                new() { Name = "token_type", Value = "Bearer" },
                new() { Name = "expires_at", Value = DateTimeOffset.UtcNow.AddMinutes(expired ? -1 : 5).ToString("o") },
                new() { Name = "refresh_token", Value = includeRefresh ? "synthetic-refresh" : "" },
                new() { Name = "id_token", Value = "synthetic-id-never-bearer" }
            ]);
            var ticket = new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "synthetic-user")], "test")),
                properties, AuthenticationExtensions.CookieScheme);
            result.Key = await result.Store.StoreAsync(ticket);
            var stored = (await result.Store.RetrieveAsync(result.Key))!;
            result._services = new ServiceCollection().AddSingleton<IAuthenticationService>(new Authentication(stored)).BuildServiceProvider();
            var context = new DefaultHttpContext { RequestServices = result._services };
            result._http = new HttpClient(result.Handler);
            result.Provider = new(result.Store, new TestContextAccessor { HttpContext = context }, new Clients(result._http),
                Options.Create(Configuration), new Monitor(), new SyntheticCredential());
            return result;
        }

        public void Dispose() { Store.Dispose(); _http.Dispose(); _services.Dispose(); }
    }

    private sealed class Handler : HttpMessageHandler
    {
        public int Calls;
        public string Form = "";
        public string? Authorization;
        public HttpStatusCode Status = HttpStatusCode.OK;
        public Exception? Failure;
        public string Json = "{\"access_token\":\"synthetic-new-access\",\"refresh_token\":\"synthetic-new-refresh\",\"id_token\":\"never-save-id\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"Banking.Read\"}";
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Calls);
            if (Failure is not null) throw Failure;
            Form = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
            Authorization = request.Headers.Authorization?.ToString();
            await Task.Delay(10, cancellationToken);
            return new(Status) { Content = new StringContent(Json, Encoding.UTF8, "application/json") };
        }
    }

    private sealed class Clients(HttpClient client) : IHttpClientFactory { public HttpClient CreateClient(string name) => client; }
    private sealed class TestContextAccessor : IHttpContextAccessor { public HttpContext? HttpContext { get; set; } }
    private sealed class SyntheticCredential : IOidcRefreshCredential
    { public void Apply(Dictionary<string, string> parameters, string tokenEndpoint) => parameters["client_assertion"] = "synthetic-assertion"; }
    private sealed class Monitor : IOptionsMonitor<OpenIdConnectOptions>
    {
        public OpenIdConnectOptions CurrentValue => Get(null);
        public OpenIdConnectOptions Get(string? name) => new()
        {
            Authority = "https://issuer.example.test", ClientId = "synthetic-client",
            ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(new()
            { Issuer = "https://issuer.example.test", TokenEndpoint = "https://issuer.example.test/token" })
        };
        public IDisposable? OnChange(Action<OpenIdConnectOptions, string?> listener) => null;
    }
    private sealed class Authentication(AuthenticationTicket ticket) : IAuthenticationService
    {
        public int SignOuts;
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) => Task.FromResult(AuthenticateResult.Success(ticket));
        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        { SignOuts++; return Task.CompletedTask; }
    }
}
