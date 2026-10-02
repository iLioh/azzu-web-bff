using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

namespace Azzu.WebBff.Infrastructure;

/// <summary>Loads a dedicated, version-pinned server PFX into ephemeral process memory.</summary>
public sealed class KeyVaultServerTlsLoader(SecretClient secrets)
{
    public static KeyVaultServerTlsLoader FromWorkloadIdentity(ServerTlsOptions options)
    {
        if (!options.IsConfigured
            || Environment.GetEnvironmentVariable("AZURE_CLIENT_ID") != options.WorkloadIdentityClientId
            || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("AZURE_FEDERATED_TOKEN_FILE"))
            || !Guid.TryParse(Environment.GetEnvironmentVariable("AZURE_TENANT_ID"), out var tenant) || tenant == Guid.Empty)
            throw new InvalidOperationException("Server TLS requires explicit Workload Identity and pinned configuration.");
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

    public async Task<ServerTlsMaterial> LoadAsync(ServerTlsOptions options, CancellationToken cancellationToken)
    {
        if (!options.IsConfigured) throw new InvalidOperationException("Server TLS configuration is incomplete.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var certificates = new X509Certificate2Collection();
        try
        {
            var secret = (await secrets.GetSecretAsync(options.Name, options.Version, timeout.Token)).Value;
            if (secret.Properties.Enabled != true || secret.Properties.ExpiresOn <= DateTimeOffset.UtcNow
                || secret.Properties.ContentType != "application/x-pkcs12" || secret.Value.Length > 128 * 1024)
                throw new InvalidOperationException("Server TLS certificate secret is not usable.");
            var bytes = Convert.FromBase64String(secret.Value);
            try { certificates.Import(bytes, (string?)null, X509KeyStorageFlags.EphemeralKeySet); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
            var leaves = certificates.Cast<X509Certificate2>().Where(certificate => certificate.HasPrivateKey).ToArray();
            if (leaves.Length != 1) throw new InvalidOperationException("Server TLS requires exactly one private-key certificate.");
            var leaf = leaves[0];
            ValidateCertificateIdentity(leaf, options);
            using var chain = new X509Chain();
            chain.ChainPolicy.ExtraStore.AddRange(certificates);
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.System;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
            chain.ChainPolicy.DisableCertificateDownloads = true;
            // Offline startup trust check only; does NOT claim a revocation check.
            // Gateway/client validation remains mandatory. Include CA intermediates in the PFX.
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            if (!chain.Build(leaf)) throw new InvalidOperationException("Server TLS chain is not system-trusted.");
            var context = SslStreamCertificateContext.Create(leaf, certificates, offline: true);
            return new ServerTlsMaterial(context, certificates);
        }
        catch (Exception error) when (error is RequestFailedException or AuthenticationFailedException
            or CryptographicException or FormatException or OperationCanceledException or InvalidOperationException)
        {
            foreach (var certificate in certificates) certificate.Dispose();
            // Never retain SDK response bodies, PFX bytes or credentials in exception messages.
            throw new InvalidOperationException("Server TLS certificate could not be loaded safely.");
        }
    }

    public static void ValidateCertificateIdentity(X509Certificate2 certificate, ServerTlsOptions options)
    {
        using var rsa = certificate.GetRSAPrivateKey();
        using var ec = certificate.GetECDsaPrivateKey();
        var basic = certificate.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
        var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
        var eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault();
        var sanExtension = certificate.Extensions.SingleOrDefault(extension => extension.Oid?.Value == "2.5.29.17");
        var sanMatches = sanExtension is not null && new X509SubjectAlternativeNameExtension(sanExtension.RawData)
            .EnumerateDnsNames().Any(name => string.Equals(name, options.Hostname, StringComparison.OrdinalIgnoreCase));
        var allowedUsage = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment;
        if (!options.IsConfigured || !certificate.HasPrivateKey
            || !(rsa?.KeySize >= 3072 || ec?.KeySize >= 256)
            || basic is null || basic.CertificateAuthority || usage is null
            || !usage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature) || (usage.KeyUsages & ~allowedUsage) != 0
            || eku is null || !eku.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == "1.3.6.1.5.5.7.3.1")
            || !sanMatches || certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow
            || certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow
            || !certificate.GetCertHashString(HashAlgorithmName.SHA256).Equals(options.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Server TLS certificate failed its identity and security checks.");
    }
}

public sealed class ServerTlsMaterial(SslStreamCertificateContext context, X509Certificate2Collection certificates) : IDisposable
{
    public SslStreamCertificateContext Context { get; } = context;
    public void Dispose()
    {
        foreach (var certificate in certificates) certificate.Dispose();
    }
}
