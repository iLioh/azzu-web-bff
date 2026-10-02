using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure;
using Azure.Security.KeyVault.Secrets;
using Azzu.WebBff.Infrastructure;
using Xunit;

namespace Azzu.WebBff.Api.Tests;

public sealed class ServerTlsTests
{
    [Fact]
    public void AcceptsPinnedServerIdentityWithExactSan()
    {
        using var certificate = Certificate();
        KeyVaultServerTlsLoader.ValidateCertificateIdentity(certificate, Options(certificate));
    }

    [Theory]
    [InlineData("expired")]
    [InlineData("future")]
    [InlineData("small-key")]
    [InlineData("wrong-san")]
    [InlineData("no-san")]
    [InlineData("ca")]
    [InlineData("client-auth")]
    [InlineData("no-eku")]
    [InlineData("unsafe-usage")]
    [InlineData("public-only")]
    [InlineData("wrong-pin")]
    public void RejectsUnsafeIdentity(string scenario)
    {
        using var certificate = Certificate(scenario);
        using var publicOnly = new X509Certificate2(certificate.RawData);
        Assert.Throws<InvalidOperationException>(() => KeyVaultServerTlsLoader.ValidateCertificateIdentity(
            scenario == "public-only" ? publicOnly : certificate,
            Options(certificate, scenario == "wrong-pin" ? new string('0', 64) : null)));
    }

    [Theory]
    [InlineData("client-certificate")]
    [InlineData("unpinned")]
    [InlineData("http")]
    [InlineData("bad-port")]
    public void RejectsInvalidConfiguration(string scenario)
    {
        var options = new ServerTlsOptions
        {
            Enabled = true, Port = scenario == "bad-port" ? 8080 : 8443,
            KeyVaultUri = scenario == "http" ? "http://vault.vault.azure.net/" : "https://vault.vault.azure.net/",
            Name = scenario == "client-certificate" ? "azzu-web-bff-dev-oidc" : "azzu-web-bff-dev-server-tls",
            Version = scenario == "unpinned" ? "" : new string('a', 32),
            ExpectedSha256 = new string('a', 64), WorkloadIdentityClientId = "6cdef73b-41a2-4aa5-b294-db6225286aed"
        };
        Assert.False(options.IsConfigured);
        Assert.Throws<InvalidOperationException>(() => KeyVaultServerTlsLoader.FromWorkloadIdentity(options));
    }

    [Fact]
    public async Task SelfSignedPfxIsNotPromotedToSystemTrust()
    {
        using var certificate = Certificate();
        var options = Options(certificate);
        var secret = new KeyVaultSecret(options.Name, Convert.ToBase64String(certificate.Export(X509ContentType.Pkcs12)));
        secret.Properties.Enabled = true;
        secret.Properties.ContentType = "application/x-pkcs12";
        secret.Properties.ExpiresOn = DateTimeOffset.UtcNow.AddHours(1);
        var client = new FakeSecrets(secret);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new KeyVaultServerTlsLoader(client).LoadAsync(options, CancellationToken.None));
        Assert.Equal(options.Name, client.RequestedName);
        Assert.Equal(options.Version, client.RequestedVersion);
        Assert.DoesNotContain(secret.Value, error.Message);
        Assert.Null(error.InnerException);
    }

    private static ServerTlsOptions Options(X509Certificate2 certificate, string? pin = null) => new()
    {
        Enabled = true, KeyVaultUri = "https://synthetic-vault.vault.azure.net/",
        Name = "azzu-web-bff-dev-server-tls", Version = new string('a', 32),
        ExpectedSha256 = pin ?? certificate.GetCertHashString(HashAlgorithmName.SHA256),
        WorkloadIdentityClientId = "6cdef73b-41a2-4aa5-b294-db6225286aed"
    };

    private static X509Certificate2 Certificate(string scenario = "valid")
    {
        using var key = RSA.Create(scenario == "small-key" ? 2048 : 3072);
        var request = new CertificateRequest("CN=web-bff.internal.azzu.tech", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(scenario == "ca", false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(scenario == "unsafe-usage"
            ? X509KeyUsageFlags.KeyCertSign : X509KeyUsageFlags.DigitalSignature, true));
        if (scenario != "no-eku") request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection
        {
            new(scenario == "client-auth" ? "1.3.6.1.5.5.7.3.2" : "1.3.6.1.5.5.7.3.1")
        }, false));
        if (scenario != "no-san")
        {
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName(scenario == "wrong-san" ? "other.internal.azzu.tech" : "web-bff.internal.azzu.tech");
            request.CertificateExtensions.Add(san.Build());
        }
        using var generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(scenario == "future" ? 1 : -2),
            DateTimeOffset.UtcNow.AddDays(scenario == "expired" ? -1 : 2));
        return new X509Certificate2(generated.Export(X509ContentType.Pkcs12), (string?)null,
            X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
    }

    private sealed class FakeSecrets(KeyVaultSecret secret) : SecretClient
    {
        public string? RequestedName { get; private set; }
        public string? RequestedVersion { get; private set; }
        public override Task<Response<KeyVaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default)
        {
            RequestedName = name; RequestedVersion = version;
            return Task.FromResult(Response.FromValue(secret, null!));
        }
    }
}
