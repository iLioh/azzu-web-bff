using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure;
using Azure.Security.KeyVault.Secrets;
using Azzu.WebBff.Infrastructure;
using Xunit;

namespace Azzu.WebBff.Api.Tests;

public sealed class KeyVaultMappingCertificateTests
{
    [Fact]
    public async Task LoadsOnlyPinnedPfxAndRetainsPrivateKeyWithoutFiles()
    {
        using var certificate = CreateCertificate();
        var options = Options(certificate);
        var secret = new KeyVaultSecret(options.KeyVaultCertificateName,
            Convert.ToBase64String(certificate.Export(X509ContentType.Pkcs12)));
        secret.Properties.Enabled = true;
        secret.Properties.ContentType = "application/x-pkcs12";
        secret.Properties.ExpiresOn = DateTimeOffset.UtcNow.AddHours(1);
        var client = new FakeSecrets(secret);
        using var loaded = await new KeyVaultMappingCertificateLoader(client).LoadAsync(options, CancellationToken.None);
        Assert.True(loaded.HasPrivateKey);
        Assert.Equal(options.ExpectedClientCertificateSha256, loaded.GetCertHashString(HashAlgorithmName.SHA256));
        Assert.Equal(options.KeyVaultCertificateName, client.RequestedName);
        Assert.Equal(options.KeyVaultCertificateVersion, client.RequestedVersion);
        using var clone = new X509Certificate2(loaded);
        Assert.True(clone.HasPrivateKey);
    }

    [Theory]
    [InlineData("wrong-hash")]
    [InlineData("small-rsa")]
    [InlineData("expired")]
    [InlineData("server-auth")]
    [InlineData("ca")]
    [InlineData("public-only")]
    public void RejectsWrongOrUnsafeClientCertificate(string scenario)
    {
        using var certificate = CreateCertificate(scenario);
        var options = Options(certificate);
        if (scenario == "wrong-hash") { options.ExpectedClientCertificateSha256 = new string('0', 64); }
        using var publicCertificate = new X509Certificate2(certificate.RawData);
        Assert.Throws<InvalidOperationException>(() => KeyVaultMappingCertificateLoader.ValidateCertificate(
            scenario == "public-only" ? publicCertificate : certificate, options));
    }

    [Fact]
    public void KeyVaultConfigurationCannotSilentlyFallBackToLocalPrivateKey()
    {
        using var certificate = CreateCertificate();
        var options = Options(certificate);
        options.ClientKeyPath = "do-not-use.key";
        Assert.Throws<InvalidOperationException>(options.Validate);
        options.ClientKeyPath = "";
        options.KeyVaultCertificateVersion = "";
        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    private static IdentityMappingOptions Options(X509Certificate2 certificate) => new()
    {
        Endpoint = "https://mapping.example/", TrustedIssuer = "https://issuer.example/",
        TenantId = "db24bd50-f509-4173-9375-d30840ec6f39", CertificateSource = "KeyVault",
        KeyVaultUri = "https://test-vault.vault.azure.net/", KeyVaultCertificateName = "mapping-client",
        KeyVaultCertificateVersion = new string('a', 32), WorkloadIdentityClientId = "6cdef73b-41a2-4aa5-b294-db6225286aed",
        ExpectedClientCertificateSha256 = certificate.GetCertHashString(HashAlgorithmName.SHA256),
        ExpectedRootCertificateSha256 = new string('a', 64), RootCertificatePath = "public-ca.crt"
    };

    private static X509Certificate2 CreateCertificate(string scenario = "valid")
    {
        using var key = RSA.Create(scenario == "small-rsa" ? 2048 : 3072);
        var request = new CertificateRequest("CN=azzu-web-bff-dev", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(scenario == "ca", false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection
        {
            new(scenario == "server-auth" ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2")
        }, false));
        using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2),
            DateTimeOffset.UtcNow.AddDays(scenario == "expired" ? -1 : 1));
        // Synthetic fixture only: exportable so the fake vault can provide its PFX on Windows.
        return new X509Certificate2(generated.Export(X509ContentType.Pkcs12), (string?)null,
            X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
    }

    private sealed class FakeSecrets(KeyVaultSecret secret) : SecretClient
    {
        public string? RequestedName { get; private set; }
        public string? RequestedVersion { get; private set; }
        public override Task<Response<KeyVaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default)
        {
            RequestedName = name;
            RequestedVersion = version;
            return Task.FromResult(Response.FromValue(secret, null!));
        }
    }
}
