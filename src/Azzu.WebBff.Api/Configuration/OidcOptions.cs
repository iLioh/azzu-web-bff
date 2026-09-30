namespace Azzu.WebBff.Api.Configuration;

public sealed class OidcOptions
{
    public const string SectionName = "Oidc";

    public string Authority { get; init; } = string.Empty;
    public string ClientId { get; init; } = string.Empty;
    public string ClientSecret { get; init; } = string.Empty;
    public string CallbackPath { get; init; } = "/signin-oidc";

    public bool IsConfigured =>
        Uri.TryCreate(Authority, UriKind.Absolute, out _) &&
        !string.IsNullOrWhiteSpace(ClientId) &&
        !string.IsNullOrWhiteSpace(ClientSecret);
}

