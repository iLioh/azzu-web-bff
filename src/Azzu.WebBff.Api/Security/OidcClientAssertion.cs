using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azzu.WebBff.Api.Configuration;
using Azzu.WebBff.Infrastructure;
using Microsoft.IdentityModel.Tokens;

namespace Azzu.WebBff.Api.Security;

public static class OidcClientAssertion
{
    public const string AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    public static string Create(OidcOptions options, X509Certificate2 certificate, string tokenEndpoint)
    {
        if (options.CredentialMode != "Certificate" || !options.IsConfigured || tokenEndpoint != options.TokenEndpoint)
            throw new InvalidOperationException("OIDC assertion destination or configuration invalid.");
        KeyVaultOidcCertificateLoader.ValidateCertificate(certificate, options.Certificate);
        var now = DateTimeOffset.UtcNow;
        var header = new JwtHeader(new SigningCredentials(new X509SecurityKey(certificate), SecurityAlgorithms.RsaSsaPssSha256));
        header.Remove("x5t");
        header.Remove("kid");
        header["x5t#S256"] = Base64UrlEncoder.Encode(certificate.GetCertHash(HashAlgorithmName.SHA256));
        var payload = new JwtPayload
        {
            ["iss"] = options.ClientId, ["sub"] = options.ClientId, ["aud"] = tokenEndpoint,
            ["jti"] = Guid.NewGuid().ToString("D"), ["iat"] = now.ToUnixTimeSeconds(),
            ["nbf"] = now.AddSeconds(-30).ToUnixTimeSeconds(), ["exp"] = now.AddMinutes(2).ToUnixTimeSeconds()
        };
        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(header, payload));
    }
}
