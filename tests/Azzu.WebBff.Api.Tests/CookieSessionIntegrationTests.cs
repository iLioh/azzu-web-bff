using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Azzu.WebBff.Api.Security;
using Azzu.WebBff.Application;
using Azzu.WebBff.Domain;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using Xunit;

namespace Azzu.WebBff.Api.Tests;

// Real cookie handler + DEV ticket store + antiforgery + production API endpoints.
// The synthetic sign-in middleware exists ONLY in this test assembly, never in the API.
public sealed class CookieSessionIntegrationTests
{
    [Fact]
    public async Task ReauthenticationRotatesReferenceAndRevokesOnlyPreviousSession()
    {
        using var factory = CreateFactory();
        using var client = CreateClient(factory);
        var original = await SignInAsync(client, "tokens");
        var unrelated = await SignInAsync(client);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/__tests/issue-session?scenario=tokens");
        request.Headers.Add("Cookie", original);
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var replacement = Cookies(response).Last(value => value.StartsWith(AuthenticationExtensions.SessionCookieName + "=", StringComparison.Ordinal))
            .Split(';', 2)[0];
        var options = factory.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(AuthenticationExtensions.CookieScheme);
        string Reference(string cookie) => Assert.Single(options.TicketDataFormat.Unprotect(cookie[(cookie.IndexOf('=') + 1)..])!
            .Principal.Claims, claim => claim.Type.EndsWith("-SessionId", StringComparison.Ordinal)).Value;
        Assert.NotEqual(Reference(original), Reference(replacement));
        using var renewed = await GetAsync(client, "/api/v1/auth/session", replacement);
        Assert.Equal(HttpStatusCode.OK, renewed.StatusCode);
        using var replay = await GetAsync(client, "/api/v1/auth/session", original);
        await AssertProblemAsync(replay, HttpStatusCode.Unauthorized, "INVALID_SESSION_CONTEXT");
        using var intact = await GetAsync(client, "/api/v1/auth/session", unrelated);
        Assert.Equal(HttpStatusCode.OK, intact.StatusCode);
    }

    [Fact]
    public async Task BrowserCookieContainsOnlyReferenceWhileTokensRemainInServerStore()
    {
        using var factory = CreateFactory();
        using var client = CreateClient(factory);
        var cookie = await SignInAsync(client, "tokens");
        var options = factory.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(AuthenticationExtensions.CookieScheme);
        var browserTicket = options.TicketDataFormat.Unprotect(cookie[(cookie.IndexOf('=') + 1)..]);
        Assert.NotNull(browserTicket);
        Assert.Empty(browserTicket.Properties.GetTokens());
        Assert.DoesNotContain(browserTicket.Principal.Claims, claim => claim.Type == "sub");
        var key = Assert.Single(browserTicket.Principal.Claims, claim => claim.Type.EndsWith("-SessionId", StringComparison.Ordinal)).Value;
        var serverTicket = await factory.Services.GetRequiredService<DevelopmentTicketStore>().RetrieveAsync(key);
        Assert.Equal("synthetic-server-access", serverTicket!.Properties.GetTokenValue("access_token"));
        Assert.Equal("synthetic-server-refresh", serverTicket.Properties.GetTokenValue("refresh_token"));
    }

    [Fact]
    public async Task LogoutRevokesServerTicketSoCopiedCookieCannotBeReplayed()
    {
        using var factory = CreateFactory();
        using var client = CreateClient(factory);
        var session = await SignInAsync(client);
        using var authenticated = await GetAsync(client, "/api/v1/auth/session", session);
        Assert.Equal(HttpStatusCode.OK, authenticated.StatusCode);
        Assert.Equal("no-store", authenticated.Headers.CacheControl?.ToString());
        var csrf = await BootstrapCsrfAsync(client, session);
        using var logout = await LogoutAsync(client, session, csrf);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        using var replay = await GetAsync(client, "/api/v1/auth/session", session);
        await AssertProblemAsync(replay, HttpStatusCode.Unauthorized, "INVALID_SESSION_CONTEXT");
    }

    [Fact]
    public async Task CsrfFromAnotherIdentityCannotLogoutVictim()
    {
        using var factory = CreateFactory();
        using var client = CreateClient(factory);
        var first = await SignInAsync(client);
        var second = await SignInAsync(client, "other");
        var csrf = await BootstrapCsrfAsync(client, first);
        using var rejected = await LogoutAsync(client, second, csrf);
        await AssertProblemAsync(rejected, HttpStatusCode.Forbidden, "CSRF_VALIDATION_FAILED");
        using var intact = await GetAsync(client, "/api/v1/auth/csrf", second);
        Assert.Equal(HttpStatusCode.NoContent, intact.StatusCode);
    }

    [Theory]
    [InlineData("unlinked", HttpStatusCode.Forbidden, "CUSTOMER_IDENTITY_NOT_LINKED")]
    [InlineData("unavailable", HttpStatusCode.ServiceUnavailable, "CUSTOMER_IDENTITY_MAPPING_UNAVAILABLE")]
    public async Task MappingFailurePreservesCookieAndStillAllowsLogout(string mode, HttpStatusCode status, string code)
    {
        using var factory = CreateFactory(mode);
        using var client = CreateClient(factory);
        var session = await SignInAsync(client);
        using var failed = await GetAsync(client, "/api/v1/auth/session", session);
        await AssertProblemAsync(failed, status, code);
        Assert.DoesNotContain(Cookies(failed), cookie => cookie.StartsWith(AuthenticationExtensions.SessionCookieName + "=", StringComparison.Ordinal));
        var csrf = await BootstrapCsrfAsync(client, session);
        using var logout = await LogoutAsync(client, session, csrf);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        using var replay = await GetAsync(client, "/api/v1/auth/csrf", session);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task ModifiedSessionCookieIsRejected()
    {
        using var factory = CreateFactory();
        using var client = CreateClient(factory);
        var cookie = await SignInAsync(client);
        var start = cookie.IndexOf('=') + 1;
        var tampered = cookie[..start] + (cookie[start] == 'A' ? 'B' : 'A') + cookie[(start + 1)..];
        using var response = await GetAsync(client, "/api/v1/auth/csrf", tampered);
        await AssertProblemAsync(response, HttpStatusCode.Unauthorized, "INVALID_SESSION_CONTEXT");
    }

    [Fact]
    public async Task ExpiredTicketCannotBootstrapCsrf()
    {
        using var factory = CreateFactory();
        using var client = CreateClient(factory);
        var session = await SignInAsync(client, "expired");
        using var response = await GetAsync(client, "/api/v1/auth/csrf", session);
        await AssertProblemAsync(response, HttpStatusCode.Unauthorized, "INVALID_SESSION_CONTEXT");
    }

    [Fact]
    public async Task AnonymousCallerCannotBootstrapCsrf()
    {
        using var factory = CreateFactory();
        using var client = CreateClient(factory);
        using var response = await client.GetAsync("/api/v1/auth/csrf");
        await AssertProblemAsync(response, HttpStatusCode.Unauthorized, "INVALID_SESSION_CONTEXT");
        Assert.DoesNotContain(Cookies(response), cookie => cookie.StartsWith("XSRF-TOKEN=", StringComparison.Ordinal));
    }

    private static WebApplicationFactory<Program> CreateFactory(string mode = "linked") =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Development");
            builder.ConfigureTestServices(services =>
            {
                services.AddSingleton<IStartupFilter, SyntheticSignInFilter>();
                services.RemoveAll<ICustomerIdentityMapping>();
                services.AddSingleton<ICustomerIdentityMapping>(new SyntheticMapping(mode));
            });
        });

    private static HttpClient CreateClient(WebApplicationFactory<Program> factory) => factory.CreateClient(new()
    {
        BaseAddress = new Uri("https://localhost"), HandleCookies = false, AllowAutoRedirect = false
    });

    private static async Task<string> SignInAsync(HttpClient client, string scenario = "linked")
    {
        using var response = await client.PostAsync("/__tests/issue-session?scenario=" + scenario, null);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var cookie = Cookies(response).Single(value => value.StartsWith(AuthenticationExtensions.SessionCookieName + "=", StringComparison.Ordinal));
        Assert.Contains("secure", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("domain=", cookie, StringComparison.OrdinalIgnoreCase);
        return cookie.Split(';', 2)[0];
    }

    private static async Task<CsrfMaterial> BootstrapCsrfAsync(HttpClient client, string session)
    {
        using var response = await GetAsync(client, "/api/v1/auth/csrf", session);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var cookie = Cookies(response).Single(value => value.StartsWith("__Host-AzzuAntiforgery=", StringComparison.Ordinal));
        var token = Cookies(response).Single(value => value.StartsWith("XSRF-TOKEN=", StringComparison.Ordinal))
            .Split(';', 2)[0]["XSRF-TOKEN=".Length..];
        return new(cookie.Split(';', 2)[0], Uri.UnescapeDataString(token));
    }

    private static async Task<HttpResponseMessage> GetAsync(HttpClient client, string path, string cookie)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Add("Cookie", cookie);
        return await client.SendAsync(request);
    }

    private static async Task<HttpResponseMessage> LogoutAsync(HttpClient client, string session, CsrfMaterial csrf)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/auth/logout");
        request.Headers.Add("Cookie", session + "; " + csrf.Cookie);
        request.Headers.Add("X-XSRF-TOKEN", csrf.Token);
        return await client.SendAsync(request);
    }

    private static async Task AssertProblemAsync(HttpResponseMessage response, HttpStatusCode status, string code)
    {
        Assert.Equal(status, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal(code, (await response.Content.ReadFromJsonAsync<Problem>())?.Code);
    }

    private static IEnumerable<string> Cookies(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Set-Cookie", out var values) ? values : [];

    private sealed record Problem(string Code);
    private sealed record CsrfMaterial(string Cookie, string Token);

    private sealed class SyntheticMapping(string mode) : ICustomerIdentityMapping
    {
        public Task<string?> ResolveCustomerIdAsync(ExternalIdentity identity, CancellationToken cancellationToken) => mode switch
        {
            "unlinked" => Task.FromResult<string?>(null),
            "unavailable" => throw new CustomerIdentityMappingUnavailableException("Synthetic outage."),
            _ => Task.FromResult<string?>("synthetic-customer")
        };
    }

    private sealed class SyntheticSignInFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, continuation) =>
            {
                if (context.Request.Path != "/__tests/issue-session")
                {
                    await continuation(context);
                    return;
                }
                var scenario = context.Request.Query["scenario"].ToString();
                var subject = scenario == "other" ? "synthetic-other" : "synthetic-user";
                var claims = new ClaimsIdentity([
                    new("iss", "https://issuer.example.test"), new("sub", subject), new("name", "Test Customer"),
                    new("oid", "00000000-0000-0000-0000-000000000001"),
                    new("tid", "db24bd50-f509-4173-9375-d30840ec6f39")
                ], AuthenticationExtensions.CookieScheme);
                var properties = new AuthenticationProperties
                {
                    IssuedUtc = DateTimeOffset.UtcNow.AddMinutes(-2),
                    ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(scenario == "expired" ? -1 : 10)
                };
                if (scenario == "tokens") properties.StoreTokens([
                    new() { Name = "access_token", Value = "synthetic-server-access" },
                    new() { Name = "refresh_token", Value = "synthetic-server-refresh" }
                ]);
                await context.SignInAsync(AuthenticationExtensions.CookieScheme, new ClaimsPrincipal(claims), properties);
                context.Response.StatusCode = StatusCodes.Status204NoContent;
            });
            next(app);
        };
    }
}
