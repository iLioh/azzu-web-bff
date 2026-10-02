namespace Azzu.WebBff.Infrastructure;

public sealed class IdentityMappingOptions
{
    public bool Enabled { get; set; }
    public string Endpoint { get; set; } = "";
    public string TrustedIssuer { get; set; } = "";
    public string TenantId { get; set; } = "";
    public int TimeoutSeconds { get; set; } = 5;
    public string ClientCertificatePath { get; set; } = "";
    public string ClientKeyPath { get; set; } = "";
    public string RootCertificatePath { get; set; } = "";
    public bool DisableRevocationCheckForDevelopment { get; set; }
    public string CertificateSource { get; set; } = "Pem";
    public string KeyVaultUri { get; set; } = "";
    public string KeyVaultCertificateName { get; set; } = "";
    public string KeyVaultCertificateVersion { get; set; } = "";
    public string WorkloadIdentityClientId { get; set; } = "";
    public string ExpectedClientCertificateSha256 { get; set; } = "";
    public string ExpectedRootCertificateSha256 { get; set; } = "";

    public void Validate()
    {
        if (!Uri.TryCreate(Endpoint, UriKind.Absolute, out var endpoint)
            || endpoint.Scheme != Uri.UriSchemeHttps
            || !string.IsNullOrEmpty(endpoint.UserInfo)
            || endpoint.AbsolutePath != "/"
            || !string.IsNullOrEmpty(endpoint.Query)
            || !string.IsNullOrEmpty(endpoint.Fragment)
            || !Uri.TryCreate(TrustedIssuer, UriKind.Absolute, out var issuer)
            || issuer.Scheme != Uri.UriSchemeHttps
            || !Guid.TryParse(TenantId, out var tenant) || tenant == Guid.Empty
            || TimeoutSeconds is < 1 or > 30
            || !ValidCertificateSource()
            || string.IsNullOrWhiteSpace(RootCertificatePath))
        {
            throw new InvalidOperationException("Identity Mapping requires explicit HTTPS, identity, timeout and mTLS configuration.");
        }
    }

    private bool ValidCertificateSource()
    {
        if (CertificateSource == "Pem")
        {
            return !string.IsNullOrWhiteSpace(ClientCertificatePath) && !string.IsNullOrWhiteSpace(ClientKeyPath)
                && string.IsNullOrEmpty(KeyVaultUri);
        }

        return CertificateSource == "KeyVault"
            && string.IsNullOrEmpty(ClientCertificatePath) && string.IsNullOrEmpty(ClientKeyPath)
            && Uri.TryCreate(KeyVaultUri, UriKind.Absolute, out var vault)
            && vault.Scheme == Uri.UriSchemeHttps && vault.Host.EndsWith(".vault.azure.net", StringComparison.Ordinal)
            && vault.AbsolutePath == "/" && vault.Port == 443 && string.IsNullOrEmpty(vault.UserInfo)
            && string.IsNullOrEmpty(vault.Query) && string.IsNullOrEmpty(vault.Fragment)
            && System.Text.RegularExpressions.Regex.IsMatch(KeyVaultCertificateName, "^[a-zA-Z0-9-]{1,127}$")
            && System.Text.RegularExpressions.Regex.IsMatch(KeyVaultCertificateVersion, "^[a-fA-F0-9]{32}$")
            && Guid.TryParse(WorkloadIdentityClientId, out var clientId) && clientId != Guid.Empty
            && IsSha256(ExpectedClientCertificateSha256) && IsSha256(ExpectedRootCertificateSha256);
    }

    private static bool IsSha256(string value) =>
        System.Text.RegularExpressions.Regex.IsMatch(value, "^[a-fA-F0-9]{64}$");
}
