using System.Globalization;
using System.Net;
using System.Text.Json;
using Azzu.WebBff.Api.Configuration;
using Azzu.WebBff.Application;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;

namespace Azzu.WebBff.Api.Security;

public interface IOidcRefreshCredential
{
    void Apply(Dictionary<string, string> parameters, string tokenEndpoint);
}

public sealed class OidcRefreshCredential(OidcOptions options,
    System.Security.Cryptography.X509Certificates.X509Certificate2? certificate) : IOidcRefreshCredential
{
    public void Apply(Dictionary<string, string> parameters, string tokenEndpoint)
    {
        if (tokenEndpoint != options.TokenEndpoint)
            throw new BankingDependencyUnavailableException("OIDC token endpoint is not trusted.");
        if (options.CredentialMode == "Certificate")
        {
            if (certificate is null) throw new BankingDependencyUnavailableException("OIDC credential is unavailable.");
            parameters["client_assertion_type"] = OidcClientAssertion.AssertionType;
            parameters["client_assertion"] = OidcClientAssertion.Create(options, certificate, tokenEndpoint);
        }
        else parameters["client_secret"] = options.ClientSecret;
    }
}

public sealed class DelegatedBankingTokens(IServerSideTokenSessionStore store,
    IHttpContextAccessor contextAccessor, IHttpClientFactory clients, IOptions<BankingTokenOptions> banking,
    IOptionsMonitor<OpenIdConnectOptions> oidcOptions, IOidcRefreshCredential credential) : IBankingAccessTokenProvider
{
    public async Task<string> GetAsync(IEnumerable<string> requiredScopes, CancellationToken cancellationToken)
    {
        var options = banking.Value;
        if (!options.Enabled) throw new BankingDependencyUnavailableException("Banking delegated access is not configured.");
        var required = requiredScopes.ToArray();
        if (required.Length == 0 || required.Any(scope => !options.Scopes.Contains(scope, StringComparer.Ordinal)))
            throw new BankingDependencyUnavailableException("The operation scope configuration is invalid.");
        var context = contextAccessor.HttpContext ?? throw new InvalidSessionContextException("A web session is required.");
        var authentication = await context.AuthenticateAsync(AuthenticationExtensions.CookieScheme);
        if (!authentication.Succeeded || authentication.Properties is null ||
            !authentication.Properties.Items.TryGetValue(IServerSideTokenSessionStore.SessionKey, out var key) || string.IsNullOrEmpty(key))
            throw new InvalidSessionContextException("A server-side web session is required.");

        return await store.UseAsync(key, async (ticket, ct) =>
        {
            var properties = ticket.Properties;
            var access = properties.GetTokenValue("access_token");
            var type = properties.GetTokenValue("token_type");
            if (!string.IsNullOrWhiteSpace(access) && string.Equals(type, "Bearer", StringComparison.OrdinalIgnoreCase) &&
                DateTimeOffset.TryParse(properties.GetTokenValue("expires_at"), CultureInfo.InvariantCulture,
                    DateTimeStyles.RoundtripKind, out var expiry) &&
                expiry > DateTimeOffset.UtcNow.AddSeconds(options.RefreshBeforeExpirySeconds))
                return access;

            var refresh = properties.GetTokenValue("refresh_token");
            if (string.IsNullOrEmpty(refresh)) throw new InvalidSessionContextException("Reauthentication is required.");
            var oidc = oidcOptions.Get(AuthenticationExtensions.OidcScheme);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(options.TimeoutSeconds));
            try
            {
                var metadata = await oidc.ConfigurationManager!.GetConfigurationAsync(timeout.Token);
                if (!Uri.TryCreate(metadata.TokenEndpoint, UriKind.Absolute, out var endpoint) || endpoint.Scheme != "https" ||
                    endpoint.Host != new Uri(oidc.Authority!).Host || !string.IsNullOrEmpty(endpoint.UserInfo))
                    throw new BankingDependencyUnavailableException("OIDC token endpoint is not trusted.");
                var parameters = new Dictionary<string, string>
                {
                    ["grant_type"] = "refresh_token", ["client_id"] = oidc.ClientId!,
                    ["refresh_token"] = refresh, ["scope"] = string.Join(' ', options.Scopes)
                };
                credential.Apply(parameters, metadata.TokenEndpoint);
                using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
                { Content = new FormUrlEncodedContent(parameters) };
                using var response = await clients.CreateClient("oidc-token-refresh").SendAsync(request, timeout.Token);
                // Never log, expose or retain the provider response/error_description.
                using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync(timeout.Token));
                var root = json.RootElement;
                if (!response.IsSuccessStatusCode)
                {
                    var error = root.TryGetProperty("error", out var errorValue) ? errorValue.GetString() : null;
                    if (error is "interaction_required" or "login_required" or "consent_required")
                        throw new BankingReauthenticationRequiredException();
                    if (error == "invalid_grant")
                    {
                        properties.StoreTokens([]);
                        throw new InvalidSessionContextException("Reauthentication is required.");
                    }
                    throw new BankingDependencyUnavailableException("The identity token service is temporarily unavailable.");
                }
                var newAccess = root.GetProperty("access_token").GetString();
                var newType = root.GetProperty("token_type").GetString();
                var lifetime = root.GetProperty("expires_in").GetInt32();
                if (string.IsNullOrWhiteSpace(newAccess) || newAccess.Any(char.IsWhiteSpace) ||
                    !string.Equals(newType, "Bearer", StringComparison.OrdinalIgnoreCase) || lifetime <= options.RefreshBeforeExpirySeconds)
                    throw new BankingDependencyUnavailableException("The identity token response is invalid.");
                if (root.TryGetProperty("scope", out var scope))
                {
                    var granted = (scope.GetString() ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (options.Scopes.Any(value => !granted.Contains(value, StringComparer.Ordinal) &&
                        !granted.Contains(value[(value.LastIndexOf('/') + 1)..], StringComparer.Ordinal)))
                        throw new BankingDependencyUnavailableException("The delegated permissions were not granted.");
                }
                var rotated = root.TryGetProperty("refresh_token", out var next) ? next.GetString() : refresh;
                properties.StoreTokens([
                    new() { Name = "access_token", Value = newAccess }, new() { Name = "token_type", Value = "Bearer" },
                    new() { Name = "refresh_token", Value = string.IsNullOrEmpty(rotated) ? refresh : rotated },
                    new() { Name = "expires_at", Value = DateTimeOffset.UtcNow.AddSeconds(lifetime).ToString("o", CultureInfo.InvariantCulture) }
                ]);
                return newAccess;
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            { throw new BankingDependencyUnavailableException("The identity token service timed out."); }
            catch (HttpRequestException)
            { throw new BankingDependencyUnavailableException("The identity token service is temporarily unavailable."); }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
            { throw new BankingDependencyUnavailableException("The identity token response is invalid."); }
        }, cancellationToken);
    }
}
