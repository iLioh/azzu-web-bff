namespace Azzu.WebBff.Api.Configuration;

public sealed class OidcOptions
{
    public const string SectionName = "Oidc";

    public string Authority { get; init; } = string.Empty;
    public string ClientId { get; init; } = string.Empty;
    public string ClientSecret { get; init; } = string.Empty;
    public string CredentialMode { get; init; } = "ClientSecret";
    public string TokenEndpoint { get; init; } = string.Empty;
    public Azzu.WebBff.Infrastructure.OidcCertificateOptions Certificate { get; init; } = new();
    public string CallbackPath { get; init; } = "/api/v1/auth/callback";

    public bool IsConfigured =>
        Uri.TryCreate(Authority, UriKind.Absolute, out var authority) &&
        authority.Scheme == Uri.UriSchemeHttps &&
        string.IsNullOrEmpty(authority.UserInfo) && string.IsNullOrEmpty(authority.Query) && string.IsNullOrEmpty(authority.Fragment) &&
        (CallbackPath == "/api/v1/auth/callback" || CallbackPath == "/signin-oidc") &&
        !string.IsNullOrWhiteSpace(ClientId) &&
        ((CredentialMode == "ClientSecret" && !string.IsNullOrWhiteSpace(ClientSecret) && string.IsNullOrEmpty(Certificate.KeyVaultUri))
         || (CredentialMode == "Certificate" && string.IsNullOrEmpty(ClientSecret)
             && Guid.TryParse(ClientId, out var id) && id != Guid.Empty && Certificate.IsConfigured
             && Uri.TryCreate(TokenEndpoint, UriKind.Absolute, out var endpoint)
             && endpoint.Scheme == "https" && endpoint.Host == authority.Host
             && endpoint.AbsoluteUri == Authority.TrimEnd('/').Replace("/v2.0", "/oauth2/v2.0/token", StringComparison.Ordinal)));
}
