using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

namespace Azzu.WebBff.Infrastructure;

/// <summary>Dedicated OIDC credential; never accepts the Mapping certificate.</summary>
public sealed class KeyVaultOidcCertificateLoader(SecretClient secrets)
{
    public static KeyVaultOidcCertificateLoader FromWorkloadIdentity(OidcCertificateOptions options)
    {
        if (!options.IsConfigured
            || Environment.GetEnvironmentVariable("AZURE_CLIENT_ID") != options.WorkloadIdentityClientId
            || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("AZURE_FEDERATED_TOKEN_FILE")))
            throw new InvalidOperationException("Explicit Workload Identity and pinned OIDC certificate configuration required.");
        var credential = new WorkloadIdentityCredential(new WorkloadIdentityCredentialOptions
        {
            ClientId = options.WorkloadIdentityClientId,
            TenantId = Environment.GetEnvironmentVariable("AZURE_TENANT_ID"),
            TokenFilePath = Environment.GetEnvironmentVariable("AZURE_FEDERATED_TOKEN_FILE")
        });
        var sdk = new SecretClientOptions();
        sdk.Retry.MaxRetries = 2;
        sdk.Retry.NetworkTimeout = TimeSpan.FromSeconds(10);
        sdk.Diagnostics.IsLoggingContentEnabled = false;
        return new(new SecretClient(new Uri(options.KeyVaultUri), credential, sdk));
    }

    public async Task<X509Certificate2> LoadAsync(OidcCertificateOptions options, CancellationToken cancellationToken)
    {
        if (!options.IsConfigured) throw new InvalidOperationException("OIDC certificate configuration is invalid.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            var secret = (await secrets.GetSecretAsync(options.Name, options.Version, timeout.Token)).Value;
            if (secret.Properties.Enabled != true || secret.Properties.ExpiresOn <= DateTimeOffset.UtcNow
                || secret.Properties.ContentType != "application/x-pkcs12" || secret.Value.Length > 128 * 1024)
                throw new InvalidOperationException("OIDC certificate secret is not usable.");
            var bytes = Convert.FromBase64String(secret.Value);
            try
            {
                var certificate = new X509Certificate2(bytes, (string?)null, X509KeyStorageFlags.EphemeralKeySet);
                try { ValidateCertificate(certificate, options); return certificate; }
                catch { certificate.Dispose(); throw; }
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        catch (Exception error) when (error is RequestFailedException or AuthenticationFailedException
            or CryptographicException or FormatException or OperationCanceledException)
        {
            throw new InvalidOperationException("OIDC certificate could not be loaded safely.");
        }
    }

    public static void ValidateCertificate(X509Certificate2 certificate, OidcCertificateOptions options)
    {
        using var rsa = certificate.GetRSAPrivateKey();
        var basic = certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
        var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
        if (!options.IsConfigured || rsa is null || rsa.KeySize < 3072 || !certificate.HasPrivateKey
            || certificate.Subject != "CN=azzu-web-bff-dev-oidc" || basic is null || basic.CertificateAuthority
            || usage?.KeyUsages != X509KeyUsageFlags.DigitalSignature
            || certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow || certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow
            || !certificate.GetCertHashString(HashAlgorithmName.SHA256).Equals(options.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("OIDC certificate failed its identity and security checks.");
    }
}
