using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Azzu.WebBff.Infrastructure;
using Xunit;

namespace Azzu.WebBff.Api.Tests;

public sealed class IdentityMappingTlsTests
{
    [Theory]
    [InlineData("mapping.example", true, true, false)]
    [InlineData("wrong.example", true, false, false)]
    [InlineData("mapping.example", false, false, false)]
    [InlineData("mapping.example", true, true, true)]
    [InlineData("wrong.example", true, false, true)]
    [InlineData("mapping.example", false, false, true)]
    public async Task MutualTlsChecksServerHostnameAndTrustedCa(string serverName, bool trustCorrectCa, bool succeeds, bool useRuntimeCertificate)
    {
        // Synthetic certificates and loopback only: no production key, DNS or on-prem access.
        using var rootKey = RSA.Create(2048);
        using var root = CreateRoot(rootKey, "Test CA");
        using var otherKey = RSA.Create(2048);
        using var otherRoot = CreateRoot(otherKey, "Other CA");
        using var serverKey = RSA.Create(2048);
        using var server = CreateLeaf(serverKey, root, serverName, serverAuth: true);
        using var clientKey = RSA.Create(2048);
        using var clientCertificate = CreateLeaf(clientKey, root, "Test BFF", serverAuth: false);
        var directory = Directory.CreateTempSubdirectory("azzu-mapping-tls-");
        try
        {
            var certPath = Path.Combine(directory.FullName, "client.crt");
            var keyPath = Path.Combine(directory.FullName, "client.key");
            var rootPath = Path.Combine(directory.FullName, "ca.crt");
            await File.WriteAllTextAsync(certPath, clientCertificate.ExportCertificatePem());
            await File.WriteAllTextAsync(keyPath, clientKey.ExportPkcs8PrivateKeyPem());
            await File.WriteAllTextAsync(rootPath, (trustCorrectCa ? root : otherRoot).ExportCertificatePem());
            var options = new IdentityMappingOptions
            {
                Endpoint = "https://mapping.example/",
                TrustedIssuer = "https://issuer.example.test/",
                TenantId = "db24bd50-f509-4173-9375-d30840ec6f39",
                ClientCertificatePath = certPath,
                ClientKeyPath = keyPath,
                RootCertificatePath = rootPath,
                DisableRevocationCheckForDevelopment = true
            };
            if (useRuntimeCertificate)
            {
                options.CertificateSource = "KeyVault";
                options.ClientCertificatePath = "";
                options.ClientKeyPath = "";
                options.KeyVaultUri = "https://test-vault.vault.azure.net/";
                options.KeyVaultCertificateName = "mapping-client";
                options.KeyVaultCertificateVersion = new string('a', 32);
                options.WorkloadIdentityClientId = "6cdef73b-41a2-4aa5-b294-db6225286aed";
                options.ExpectedClientCertificateSha256 = clientCertificate.GetCertHashString(HashAlgorithmName.SHA256);
                options.ExpectedRootCertificateSha256 = (trustCorrectCa ? root : otherRoot).GetCertHashString(HashAlgorithmName.SHA256);
            }

            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var acceptedClientCertificate = false;
            var serve = ServeAsync();
            using var ownedTransport = IdentityMappingTransport.Create(options, useRuntimeCertificate ? clientCertificate : null);
            var handler = Assert.IsType<SocketsHttpHandler>(Assert.IsAssignableFrom<DelegatingHandler>(ownedTransport).InnerHandler);
            Assert.Null(handler.SslOptions.RemoteCertificateValidationCallback);
            Assert.False(handler.AllowAutoRedirect);
            Assert.False(handler.UseCookies);
            handler.ConnectCallback = async (_, token) =>
            {
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    await socket.ConnectAsync(IPAddress.Loopback, port, token);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            };
            using var http = new HttpClient(ownedTransport) { Timeout = TimeSpan.FromSeconds(5) };
            if (succeeds)
            {
                using var response = await http.GetAsync(new Uri($"https://mapping.example:{port}/"), cancellation.Token);
                Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            }
            else
            {
                await Assert.ThrowsAsync<HttpRequestException>(() =>
                    http.GetAsync(new Uri($"https://mapping.example:{port}/"), cancellation.Token));
            }

            await serve;
            if (succeeds)
            {
                Assert.True(acceptedClientCertificate);
            }

            async Task ServeAsync()
            {
                using var connection = await listener.AcceptTcpClientAsync(cancellation.Token);
                using var tls = new SslStream(connection.GetStream());
                try
                {
                    await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = server,
                        ClientCertificateRequired = true,
                        EnabledSslProtocols = SslProtocols.Tls12,
                        RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                        {
                            acceptedClientCertificate = certificate?.GetCertHashString() == clientCertificate.GetCertHashString();
                            return acceptedClientCertificate;
                        }
                    }, cancellation.Token);
                    var bytes = new byte[4096];
                    await tls.ReadAsync(bytes, cancellation.Token);
                    await tls.WriteAsync(Encoding.ASCII.GetBytes(
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"), cancellation.Token);
                }
                catch (Exception exception) when (exception is AuthenticationException or IOException)
                {
                    // Expected server-side close when the client rejects our certificate.
                }
            }
        }
        finally
        {
            // Only the uniquely created temporary test directory is removed.
            directory.Delete(recursive: true);
        }
    }

    private static X509Certificate2 CreateRoot(RSA key, string commonName)
    {
        var request = new CertificateRequest($"CN={commonName}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(2));
    }

    private static X509Certificate2 CreateLeaf(RSA key, X509Certificate2 root, string name, bool serverAuth)
    {
        var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new(serverAuth ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2") }, true));
        if (serverAuth)
        {
            var san = new SubjectAlternativeNameBuilder();
            san.AddDnsName(name);
            request.CertificateExtensions.Add(san.Build());
        }

        using var certificate = request.Create(root, DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddDays(1), RandomNumberGenerator.GetBytes(16));
        using var keyed = certificate.CopyWithPrivateKey(key);
        return new X509Certificate2(keyed.Export(X509ContentType.Pkcs12));
    }
}
