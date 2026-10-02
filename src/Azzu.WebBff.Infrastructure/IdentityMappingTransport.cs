using System.Security.Cryptography.X509Certificates;

namespace Azzu.WebBff.Infrastructure;

public static class IdentityMappingTransport
{
    public static HttpMessageHandler Create(IdentityMappingOptions options, X509Certificate2? runtimeCertificate = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        using var pem = options.CertificateSource == "KeyVault"
            ? new X509Certificate2(runtimeCertificate ?? throw new InvalidOperationException("Mapping runtime certificate has not been loaded."))
            : X509Certificate2.CreateFromPemFile(options.ClientCertificatePath, options.ClientKeyPath);
        // Schannel on Windows cannot use the ephemeral key produced by CreateFromPemFile.
        var certificate = options.CertificateSource == "KeyVault"
            ? new X509Certificate2(pem)
            : OperatingSystem.IsWindows()
            ? new X509Certificate2(pem.Export(X509ContentType.Pkcs12))
            : X509Certificate2.CreateFromPemFile(options.ClientCertificatePath, options.ClientKeyPath);
        var root = X509Certificate2.CreateFromPem(File.ReadAllText(options.RootCertificatePath));
        if (options.CertificateSource == "KeyVault"
            && !root.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256)
                .Equals(options.ExpectedRootCertificateSha256, StringComparison.OrdinalIgnoreCase))
        {
            certificate.Dispose();
            root.Dispose();
            throw new InvalidOperationException("Mapping root certificate fingerprint does not match.");
        }
        var now = DateTime.UtcNow;
        if (!certificate.HasPrivateKey || certificate.NotBefore > now || certificate.NotAfter <= now)
        {
            certificate.Dispose();
            root.Dispose();
            throw new InvalidOperationException("The Mapping client certificate is not usable.");
        }

        var policy = new X509ChainPolicy
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            VerificationFlags = X509VerificationFlags.NoFlag,
            DisableCertificateDownloads = true,
            RevocationMode = options.DisableRevocationCheckForDevelopment ? X509RevocationMode.NoCheck : X509RevocationMode.Online
        };
        policy.CustomTrustStore.Add(root);
        policy.ApplicationPolicy.Add(new System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1"));
        var transport = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            ConnectTimeout = TimeSpan.FromSeconds(options.TimeoutSeconds),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            SslOptions = new System.Net.Security.SslClientAuthenticationOptions
            {
                ClientCertificates = new X509CertificateCollection { certificate },
                CertificateChainPolicy = policy
                // No validation callback: hostname and chain are checked by the TLS runtime.
            }
        };
        return new CertificateOwningHandler(transport, certificate, root);
    }

    private sealed class CertificateOwningHandler(
        HttpMessageHandler transport,
        X509Certificate2 certificate,
        X509Certificate2 root) : DelegatingHandler(transport)
    {
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing)
            {
                certificate.Dispose();
                root.Dispose();
            }
        }
    }
}
