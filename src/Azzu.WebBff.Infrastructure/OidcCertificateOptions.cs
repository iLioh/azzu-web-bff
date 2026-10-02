using System.Text.RegularExpressions;

namespace Azzu.WebBff.Infrastructure;

public sealed class OidcCertificateOptions
{
    public string KeyVaultUri { get; init; } = "";
    public string Name { get; init; } = "";
    public string Version { get; init; } = "";
    public string WorkloadIdentityClientId { get; init; } = "";
    public string ExpectedSha256 { get; init; } = "";

    public bool IsConfigured =>
        Uri.TryCreate(KeyVaultUri, UriKind.Absolute, out var vault)
        && vault.Scheme == "https" && vault.Host.EndsWith(".vault.azure.net", StringComparison.Ordinal)
        && vault.Port == 443 && vault.AbsolutePath == "/" && vault.UserInfo == "" && vault.Query == "" && vault.Fragment == ""
        && Name == "azzu-web-bff-dev-oidc"
        && Regex.IsMatch(Version, "^[a-fA-F0-9]{32}$")
        && Guid.TryParse(WorkloadIdentityClientId, out var id) && id != Guid.Empty
        && Regex.IsMatch(ExpectedSha256, "^[a-fA-F0-9]{64}$");
}
