using System.Text.RegularExpressions;

namespace Azzu.WebBff.Infrastructure;

public sealed class ServerTlsOptions
{
    public bool Enabled { get; init; }
    public int Port { get; init; } = 8443;
    public string Hostname { get; init; } = "web-bff.internal.azzu.tech";
    public string KeyVaultUri { get; init; } = "";
    public string Name { get; init; } = "";
    public string Version { get; init; } = "";
    public string ExpectedSha256 { get; init; } = "";
    public string WorkloadIdentityClientId { get; init; } = "";

    public bool IsConfigured => Enabled && Port == 8443 && Hostname == "web-bff.internal.azzu.tech"
        && Uri.TryCreate(KeyVaultUri, UriKind.Absolute, out var vault)
        && vault.Scheme == "https" && vault.Host.EndsWith(".vault.azure.net", StringComparison.Ordinal)
        && vault.Port == 443 && vault.AbsolutePath == "/" && vault.UserInfo == ""
        && vault.Query == "" && vault.Fragment == ""
        && Name == "azzu-web-bff-dev-server-tls"
        && Regex.IsMatch(Version, "^[a-fA-F0-9]{32}$")
        && Regex.IsMatch(ExpectedSha256, "^[a-fA-F0-9]{64}$")
        && Guid.TryParse(WorkloadIdentityClientId, out var clientId) && clientId != Guid.Empty;
}
