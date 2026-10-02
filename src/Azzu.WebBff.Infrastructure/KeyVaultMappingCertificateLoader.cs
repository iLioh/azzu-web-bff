using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

namespace Azzu.WebBff.Infrastructure;

/// <summary>Reads exactly one pinned certificate secret into ephemeral process memory.</summary>
public sealed class KeyVaultMappingCertificateLoader(SecretClient secrets)
{
    public static KeyVaultMappingCertificateLoader FromWorkloadIdentity(IdentityMappingOptions options)
    {
        options.Validate();
        if (options.CertificateSource != "KeyVault"
            || !string.Equals(Environment.GetEnvironmentVariable("AZURE_CLIENT_ID"), options.WorkloadIdentityClientId, StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("AZURE_FEDERATED_TOKEN_FILE")))
        {
            throw new InvalidOperationException("Explicit AKS Workload Identity is required for Mapping certificate access.");
        }

        var credential = new WorkloadIdentityCredential(new WorkloadIdentityCredentialOptions
        {
            ClientId = options.WorkloadIdentityClientId,
            TenantId = Environment.GetEnvironmentVariable("AZURE_TENANT_ID"),
            TokenFilePath = Environment.GetEnvironmentVariable("AZURE_FEDERATED_TOKEN_FILE")
        });
        var sdkOptions = new SecretClientOptions();
        sdkOptions.Retry.Mode = RetryMode.Exponential;
        sdkOptions.Retry.MaxRetries = 2;
        sdkOptions.Retry.NetworkTimeout = TimeSpan.FromSeconds(10);
        sdkOptions.Diagnostics.IsLoggingContentEnabled = false;
        return new(new SecretClient(new Uri(options.KeyVaultUri), credential, sdkOptions));
    }

    public async Task<X509Certificate2> LoadAsync(IdentityMappingOptions options, CancellationToken cancellationToken)
    {
        options.Validate();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            var response = await secrets.GetSecretAsync(options.KeyVaultCertificateName,
                options.KeyVaultCertificateVersion, cancellationToken: timeout.Token);
            var secret = response.Value;
            if (secret.Properties.Enabled != true || secret.Properties.ExpiresOn <= DateTimeOffset.UtcNow
                || secret.Properties.ContentType != "application/x-pkcs12" || secret.Value.Length > 128 * 1024)
            {
                throw new InvalidOperationException("Mapping certificate secret is not usable.");
            }

            var pfx = Convert.FromBase64String(secret.Value);
            try
            {
                var certificate = new X509Certificate2(pfx, (string?)null, X509KeyStorageFlags.EphemeralKeySet);
                try
                {
                    ValidateCertificate(certificate, options);
                    return certificate;
                }
                catch
                {
                    certificate.Dispose();
                    throw;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pfx);
            }
        }
        catch (Exception error) when (error is RequestFailedException or AuthenticationFailedException
                                      or CryptographicException or FormatException or OperationCanceledException)
        {
            // Do not carry Azure response bodies, token assertions, secret values or PFX to logs.
            throw new InvalidOperationException("Mapping runtime certificate could not be loaded safely.");
        }
    }

    public static void ValidateCertificate(X509Certificate2 certificate, IdentityMappingOptions options)
    {
        using var rsa = certificate.GetRSAPrivateKey();
        var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
        var eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault();
        var basic = certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
        if (!certificate.HasPrivateKey || rsa is null || rsa.KeySize < 3072
            || certificate.Subject != "CN=azzu-web-bff-dev"
            || certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow || certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow
            || basic is null || basic.CertificateAuthority || usage?.KeyUsages != X509KeyUsageFlags.DigitalSignature
            || eku is null || !eku.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == "1.3.6.1.5.5.7.3.2")
            || !certificate.GetCertHashString(HashAlgorithmName.SHA256).Equals(options.ExpectedClientCertificateSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Mapping client certificate failed its identity and security checks.");
        }
    }
}
