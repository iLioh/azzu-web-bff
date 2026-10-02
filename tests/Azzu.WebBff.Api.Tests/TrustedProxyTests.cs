using System.Net;
using Azzu.WebBff.Api.Security;
using Microsoft.AspNetCore.Authentication;
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

public sealed class TrustedProxyTests
{
    [Theory]
    [InlineData("10.20.0.9", "banca.azzu.tech", "https://banca.azzu.tech/api/v1/auth/callback")]
    [InlineData("10.20.0.8", "banca.azzu.tech", "https://web-bff.internal.azzu.tech/api/v1/auth/callback")]
    [InlineData("10.20.0.9", "evil.example.test", "https://web-bff.internal.azzu.tech/api/v1/auth/callback")]
    public async Task OidcCallbackHonorsOnlyTrustedProxyAndAllowedHost(string peer, string forwardedHost, string expected)
    {
        var configuration = Configuration("10.20.0.9", "banca.azzu.tech");
        using var server = new TestServer(new WebHostBuilder().ConfigureServices(services =>
        {
            services.AddRouting();
            services.AddAzzuAuthentication(configuration);
            services.AddAzzuTrustedProxy(configuration);
            services.PostConfigure<OpenIdConnectOptions>(AuthenticationExtensions.OidcScheme, options =>
                options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(new()
                {
                    Issuer = "https://issuer.example.test", AuthorizationEndpoint = "https://issuer.example.test/authorize",
                    TokenEndpoint = "https://issuer.example.test/token"
                }));
        }).Configure(app =>
        {
            app.Use((context, next) => { context.Connection.RemoteIpAddress = IPAddress.Parse(peer); return next(context); });
            app.UseForwardedHeaders();
            app.Run(context => context.ChallengeAsync(AuthenticationExtensions.OidcScheme,
                new AuthenticationProperties { RedirectUri = "/portal/inicio" }));
        }));
        using var client = server.CreateClient();
        client.BaseAddress = new Uri("https://web-bff.internal.azzu.tech");
        using var request = new HttpRequestMessage(HttpMethod.Get, "/challenge");
        request.Headers.Add("X-Forwarded-Host", forwardedHost);
        request.Headers.Add("X-Forwarded-Proto", "https");
        request.Headers.Add("X-Forwarded-For", "192.0.2.1");
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal(expected, QueryHelpers.ParseQuery(response.Headers.Location!.Query)["redirect_uri"].ToString());
    }

    [Theory]
    [InlineData("", "banca.azzu.tech")]
    [InlineData("0.0.0.0", "banca.azzu.tech")]
    [InlineData("::", "banca.azzu.tech")]
    [InlineData("10.20.0.9", "*")]
    [InlineData("10.20.0.9", "")]
    public void UnsafeOrIncompleteProxyTrustIsRejected(string proxy, string host) =>
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddAzzuTrustedProxy(Configuration(proxy, host)));

    [Fact]
    public void DisabledForwardingNeedsNoGuessedAddresses() =>
        new ServiceCollection().AddAzzuTrustedProxy(new ConfigurationBuilder().Build());

    private static IConfiguration Configuration(string proxy, string host) => new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Oidc:Authority"] = "https://issuer.example.test", ["Oidc:ClientId"] = "test-bff",
            ["Oidc:ClientSecret"] = "synthetic-not-a-real-secret", ["Gateway:ForwardedHeadersEnabled"] = "true",
            ["Gateway:TrustedProxyAddresses:0"] = proxy, ["Gateway:AllowedForwardedHosts:0"] = host
        }).Build();
}
