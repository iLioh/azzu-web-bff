using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure;
using Azure.Security.KeyVault.Secrets;
using Azzu.WebBff.Api.Configuration;
using Azzu.WebBff.Api.Security;
using Azzu.WebBff.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Azzu.WebBff.Api.Tests;

public sealed class OidcCertificateTests
{
    private const string Client = "cecb6910-e653-4129-8376-c044209a751e";
    private const string Authority = "https://db24bd50-f509-4173-9375-d30840ec6f39.ciamlogin.com/db24bd50-f509-4173-9375-d30840ec6f39/v2.0";
    private const string Endpoint = "https://db24bd50-f509-4173-9375-d30840ec6f39.ciamlogin.com/db24bd50-f509-4173-9375-d30840ec6f39/oauth2/v2.0/token";

    [Fact]
    public async Task LoaderRequestsPinnedVersionAndImportsPrivateKeyEphemerally()
    {
        using var generated = Certificate();
        using var fixture = new X509Certificate2(generated.Export(X509ContentType.Pkcs12), (string?)null,
            X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
        var settings = Options(fixture).Certificate;
        var bytes = fixture.Export(X509ContentType.Pkcs12);
        try
        {
            var secret = new KeyVaultSecret(settings.Name, Convert.ToBase64String(bytes));
            secret.Properties.Enabled = true;
            secret.Properties.ContentType = "application/x-pkcs12";
            var fake = new FakeSecrets(secret);
            using var loaded = await new KeyVaultOidcCertificateLoader(fake).LoadAsync(settings, CancellationToken.None);
            Assert.True(loaded.HasPrivateKey);
            Assert.Equal(settings.Version, fake.Version);
            Assert.Equal(settings.Name, fake.Name);
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    [Fact]
    public async Task LoaderRejectsDisabledSecretBeforeParsingValue()
    {
        using var cert = Certificate();
        var secret = new KeyVaultSecret("azzu-web-bff-dev-oidc", "not-a-pfx");
        secret.Properties.Enabled = false;
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new KeyVaultOidcCertificateLoader(new FakeSecrets(secret)).LoadAsync(Options(cert).Certificate, CancellationToken.None));
        Assert.DoesNotContain("not-a-pfx", error.ToString());
    }

    [Fact]
    public void AssertionHasValidSignatureShortLifetimeAndApplicationOnlyClaims()
    {
        using var cert = Certificate();
        var options = Options(cert);
        var encoded = OidcClientAssertion.Create(options, cert, Endpoint);
        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        handler.ValidateToken(encoded, new TokenValidationParameters
        {
            ValidateIssuer = true, ValidIssuer = Client, ValidateAudience = true, ValidAudience = Endpoint,
            ValidateLifetime = true, RequireExpirationTime = true, RequireSignedTokens = true,
            ValidateIssuerSigningKey = true, IssuerSigningKey = new X509SecurityKey(cert),
            ValidAlgorithms = [SecurityAlgorithms.RsaSsaPssSha256], ClockSkew = TimeSpan.FromSeconds(30)
        }, out var validated);
        var jwt = Assert.IsType<JwtSecurityToken>(validated);
        Assert.Equal("PS256", jwt.Header.Alg);
        Assert.Equal(Base64UrlEncoder.Encode(cert.GetCertHash(HashAlgorithmName.SHA256)), jwt.Header["x5t#S256"]);
        Assert.Equal(Client, jwt.Subject);
        Assert.InRange(jwt.ValidTo - jwt.IssuedAt, TimeSpan.FromSeconds(119), TimeSpan.FromSeconds(121));
        Assert.Equal(7, jwt.Payload.Count);
        var next = handler.ReadJwtToken(OidcClientAssertion.Create(options, cert, Endpoint));
        Assert.NotEqual(jwt.Id, next.Id);
    }

    [Theory]
    [InlineData("https://attacker.example/token")]
    [InlineData(Endpoint + "?redirect=bad")]
    public void AssertionCannotBeSentToAnotherDestination(string destination)
    {
        using var cert = Certificate();
        Assert.Throws<InvalidOperationException>(() => OidcClientAssertion.Create(Options(cert), cert, destination));
    }

    [Fact]
    public void MappingCertificateCannotAuthenticateOidc()
    {
        using var cert = Certificate("CN=azzu-web-bff-dev");
        Assert.Throws<InvalidOperationException>(() => OidcClientAssertion.Create(Options(cert), cert, Endpoint));
    }

    [Fact]
    public void WrongPinAndMissingRuntimeCertificateFailClosed()
    {
        using var cert = Certificate();
        var options = Options(cert, new string('0', 64));
        Assert.Throws<InvalidOperationException>(() => OidcClientAssertion.Create(options, cert, Endpoint));
        var config = Configuration(cert);
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddAzzuAuthentication(config));
    }

    [Fact]
    public async Task OidcCodeRedemptionUsesAssertionNotSecretAndPreservesPkce()
    {
        using var cert = Certificate();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAzzuAuthentication(Configuration(cert), cert);
        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get(AuthenticationExtensions.OidcScheme);
        options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(new() { TokenEndpoint = Endpoint });
        var context = new AuthorizationCodeReceivedContext(new DefaultHttpContext(),
            new AuthenticationScheme(AuthenticationExtensions.OidcScheme, null, typeof(OpenIdConnectHandler)), options,
            new AuthenticationProperties())
        {
            TokenEndpointRequest = new OpenIdConnectMessage { Code = "synthetic-code", ClientSecret = "must-be-removed" }
        };
        context.TokenEndpointRequest.SetParameter("code_verifier", "synthetic-verifier");
        await options.Events.OnAuthorizationCodeReceived(context);
        Assert.Null(context.TokenEndpointRequest.ClientSecret);
        Assert.Equal(OidcClientAssertion.AssertionType, context.TokenEndpointRequest.GetParameter("client_assertion_type"));
        Assert.NotEmpty(context.TokenEndpointRequest.GetParameter("client_assertion"));
        Assert.Equal("synthetic-verifier", context.TokenEndpointRequest.GetParameter("code_verifier"));
        Assert.Equal("synthetic-code", context.TokenEndpointRequest.Code);
    }

    [Fact]
    public void CertificateModeRejectsSecretMixingAndUnsafeEndpoint()
    {
        using var cert = Certificate();
        var config = Configuration(cert);
        config["Oidc:ClientSecret"] = "synthetic";
        Assert.False(config.GetSection("Oidc").Get<OidcOptions>()!.IsConfigured);
        config["Oidc:ClientSecret"] = "";
        config["Oidc:TokenEndpoint"] = "https://attacker.example/token";
        Assert.False(config.GetSection("Oidc").Get<OidcOptions>()!.IsConfigured);
    }

    private static IConfigurationRoot Configuration(X509Certificate2 cert) => new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Oidc:Authority"] = Authority, ["Oidc:ClientId"] = Client,
            ["Oidc:CredentialMode"] = "Certificate", ["Oidc:TokenEndpoint"] = Endpoint,
            ["Oidc:Certificate:KeyVaultUri"] = "https://kv-azzu-web-dev-8466fe.vault.azure.net/",
            ["Oidc:Certificate:Name"] = "azzu-web-bff-dev-oidc",
            ["Oidc:Certificate:Version"] = new string('1', 32),
            ["Oidc:Certificate:WorkloadIdentityClientId"] = "6cdef73b-41a2-4aa5-b294-db6225286aed",
            ["Oidc:Certificate:ExpectedSha256"] = cert.GetCertHashString(HashAlgorithmName.SHA256)
        }).Build();

    private static OidcOptions Options(X509Certificate2 cert, string? pin = null)
    {
        var config = Configuration(cert);
        if (pin is not null) config["Oidc:Certificate:ExpectedSha256"] = pin;
        return config.GetSection("Oidc").Get<OidcOptions>()!;
    }

    private static X509Certificate2 Certificate(string subject = "CN=azzu-web-bff-dev-oidc")
    {
        using var rsa = RSA.Create(3072);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private sealed class FakeSecrets(KeyVaultSecret secret) : SecretClient
    {
        public string? Name { get; private set; }
        public string? Version { get; private set; }
        public override Task<Response<KeyVaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default)
        {
            Name = name; Version = version;
            return Task.FromResult(Response.FromValue(secret, null!));
        }
    }
}
