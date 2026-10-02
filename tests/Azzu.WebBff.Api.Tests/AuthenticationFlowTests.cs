using System.Security.Claims;
using Azzu.WebBff.Api.Configuration;
using Azzu.WebBff.Api.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Xunit;

namespace Azzu.WebBff.Api.Tests;

public sealed class AuthenticationFlowTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RealOidcHandlerSendsPkceAndStepUpClaims(bool stepUp)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Oidc:Authority"] = "https://issuer.example.test",
            ["Oidc:ClientId"] = "synthetic-client",
            ["Oidc:ClientSecret"] = "synthetic-not-a-real-secret"
        }).Build();
        var metadata = new OpenIdConnectConfiguration
        {
            Issuer = "https://issuer.example.test",
            AuthorizationEndpoint = "https://issuer.example.test/authorize",
            TokenEndpoint = "https://issuer.example.test/token"
        };
        using var server = new TestServer(new WebHostBuilder()
            .ConfigureServices(services =>
            {
                services.AddRouting();
                services.AddAzzuAuthentication(configuration);
                services.PostConfigure<OpenIdConnectOptions>(AuthenticationExtensions.OidcScheme, options =>
                    options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(metadata));
            })
            .Configure(app => app.Run(context =>
            {
                var properties = stepUp
                    ? new StepUpChallengeFactory(Options.Create(new StepUpOptions
                    {
                        AuthenticationContexts = new Dictionary<string, string> { ["transfers.create"] = "c1" }
                    })).Create("transfers.create", "/portal/transferencias")
                    : new AuthenticationProperties { RedirectUri = "/portal/inicio" };
                return context.ChallengeAsync(AuthenticationExtensions.OidcScheme, properties);
            })));
        using var client = server.CreateClient();
        client.BaseAddress = new Uri("https://localhost");
        using var response = await client.GetAsync("/challenge");
        Assert.Equal(System.Net.HttpStatusCode.Redirect, response.StatusCode);
        var location = Assert.IsType<Uri>(response.Headers.Location);
        Assert.Equal("issuer.example.test", location.Host);
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal("code", query["response_type"].ToString());
        Assert.Equal("S256", query["code_challenge_method"].ToString());
        Assert.NotEmpty(query["code_challenge"].ToString());
        Assert.Equal("https://localhost/api/v1/auth/callback", query["redirect_uri"].ToString());
        Assert.False(query.ContainsKey("client_secret"));
        Assert.False(query.ContainsKey("acr_values"));
        if (stepUp)
        {
            using var claims = System.Text.Json.JsonDocument.Parse(query["claims"].ToString());
            var acrs = claims.RootElement.GetProperty("id_token").GetProperty("acrs");
            Assert.True(acrs.GetProperty("essential").GetBoolean());
            Assert.Equal("c1", acrs.GetProperty("value").GetString());
        }
        else
        {
            Assert.False(query.ContainsKey("claims"));
        }
    }

    [Fact]
    public void DelegatedOidcRequestsExplicitApiScopesAndOfflineAccess()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Oidc:Authority"] = "https://issuer.example.test", ["Oidc:ClientId"] = "synthetic-bff",
            ["Oidc:ClientSecret"] = "synthetic-not-real", ["Oidc:TokenEndpoint"] = "https://issuer.example.test/token",
            ["BankingTokens:Enabled"] = "true", ["BankingTokens:Audience"] = "11111111-1111-1111-1111-111111111111",
            ["BankingTokens:AppIdUri"] = "api://11111111-1111-1111-1111-111111111111",
            ["BankingTokens:BaseUrl"] = "https://banking.example.test/api/",
            ["BankingTokens:Scopes:0"] = "api://11111111-1111-1111-1111-111111111111/Banking.Read"
        }).Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAzzuAuthentication(configuration);
        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get(AuthenticationExtensions.OidcScheme);
        Assert.True(options.SaveTokens);
        Assert.True(options.UsePkce);
        Assert.Contains("offline_access", options.Scope);
        Assert.Contains("api://11111111-1111-1111-1111-111111111111/Banking.Read", options.Scope);
        Assert.DoesNotContain(".default", options.Scope);
    }

    [Theory]
    [InlineData("https://evil.example", "/portal/inicio")]
    [InlineData("//evil.example", "/portal/inicio")]
    [InlineData("/portal/../api", "/portal/inicio")]
    [InlineData("/portal/%2f%2fevil", "/portal/inicio")]
    [InlineData("/portal//evil", "/portal/inicio")]
    [InlineData("/portal/\nevil", "/portal/inicio")]
    [InlineData("/portal/productos/tarjetas?secret=value#section", "/portal/productos/tarjetas")]
    public void ReturnDestinationCannotEscapePortal(string supplied, string expected) =>
        Assert.Equal(expected, PortalReturnUrl.Normalize(supplied));

    [Theory]
    [InlineData("http://issuer.example")]
    [InlineData("https://user:secret@issuer.example")]
    [InlineData("https://issuer.example?secret=value")]
    public void OidcDoesNotAcceptUnsafeAuthority(string authority) =>
        Assert.False(new OidcOptions { Authority = authority, ClientId = "test", ClientSecret = "not-real" }.IsConfigured);

    [Fact]
    public async Task DevelopmentStoreUsesOpaqueKeysAndRevokesTickets()
    {
        using var store = new DevelopmentTicketStore();
        var ticket = Ticket(DateTimeOffset.UtcNow.AddMinutes(5));
        var first = await store.StoreAsync(ticket);
        var second = await store.StoreAsync(ticket);
        Assert.Equal(64, first.Length);
        Assert.NotEqual(first, second);
        Assert.DoesNotContain("test-subject", first, StringComparison.Ordinal);
        Assert.NotNull(await store.RetrieveAsync(first));
        await store.RemoveAsync(first);
        Assert.Null(await store.RetrieveAsync(first));
        Assert.NotNull(await store.RetrieveAsync(second));
    }

    [Fact]
    public async Task DevelopmentStoreDoesNotKeepExpiredTickets()
    {
        using var store = new DevelopmentTicketStore();
        var key = await store.StoreAsync(Ticket(DateTimeOffset.UtcNow.AddMinutes(-1)));
        Assert.Null(await store.RetrieveAsync(key));
    }

    [Fact]
    public void StepUpCannotSwitchToAnotherCustomerEvenWithCorrectAcrs()
    {
        var factory = new StepUpChallengeFactory(Options.Create(new StepUpOptions
        {
            AuthenticationContexts = new Dictionary<string, string> { ["transfers.create"] = "c1" }
        }));
        var properties = factory.Create("transfers.create", "/portal/inicio");
        var first = Identity("00000000-0000-0000-0000-000000000001");
        StepUpChallengeFactory.BindIdentity(properties, first);
        Assert.True(StepUpChallengeFactory.HasRequiredContext(properties, first));
        Assert.False(StepUpChallengeFactory.HasRequiredContext(properties, Identity("00000000-0000-0000-0000-000000000002")));
        Assert.False(StepUpChallengeFactory.HasRequiredContext(properties, new ClaimsPrincipal()));
    }

    private static ClaimsPrincipal Identity(string oid) => new(new ClaimsIdentity([
        new Claim("iss", "https://issuer.example.test"), new Claim("sub", "app-specific-sub"),
        new Claim("oid", oid), new Claim("tid", "db24bd50-f509-4173-9375-d30840ec6f39"), new Claim("acrs", "c1")
    ], "Test"));

    private static AuthenticationTicket Ticket(DateTimeOffset expiry) => new(
        new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "test-subject")], "Test")),
        new AuthenticationProperties { ExpiresUtc = expiry }, AuthenticationExtensions.CookieScheme);
}
