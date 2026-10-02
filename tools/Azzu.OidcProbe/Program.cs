using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text.Json;
using Azzu.WebBff.Api.Configuration;
using Azzu.WebBff.Api.Security;
using Azzu.WebBff.Infrastructure;
using Microsoft.IdentityModel.Tokens;

// Isolated diagnostic, not an API/authentication bypass. No customer credentials or real codes.
try
{
    if (Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT") != "Development")
        throw new InvalidOperationException("Diagnostic is DEV only.");
    var options = new OidcOptions
    {
        Authority = "https://db24bd50-f509-4173-9375-d30840ec6f39.ciamlogin.com/db24bd50-f509-4173-9375-d30840ec6f39/v2.0",
        ClientId = "cecb6910-e653-4129-8376-c044209a751e", CredentialMode = "Certificate",
        TokenEndpoint = "https://db24bd50-f509-4173-9375-d30840ec6f39.ciamlogin.com/db24bd50-f509-4173-9375-d30840ec6f39/oauth2/v2.0/token",
        Certificate = new()
        {
            KeyVaultUri = "https://kv-azzu-web-dev-8466fe.vault.azure.net/", Name = "azzu-web-bff-dev-oidc",
            Version = "7b26223af44044f59f9dade838281b48",
            WorkloadIdentityClientId = "6cdef73b-41a2-4aa5-b294-db6225286aed",
            ExpectedSha256 = "EAA49FE5E655615D42EC2B3434DAEFA017CF32E771330DAC37627411522281CE"
        }
    };
    var ips = await Dns.GetHostAddressesAsync(new Uri(options.Certificate.KeyVaultUri).Host);
    if (ips.Length == 0 || ips.Any(ip => ip.ToString() != "10.20.5.22"))
        throw new InvalidOperationException("Private DNS gate failed.");
    Console.WriteLine("PRIVATE_VAULT_DNS_PASS");
    using var certificate = await KeyVaultOidcCertificateLoader.FromWorkloadIdentity(options.Certificate)
        .LoadAsync(options.Certificate, CancellationToken.None);
    Console.WriteLine("OIDC_WORKLOAD_IDENTITY_CERTIFICATE_LOAD_PASS");
    var assertion = OidcClientAssertion.Create(options, certificate, options.TokenEndpoint);
    new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(assertion, new()
    {
        ValidIssuer = options.ClientId, ValidAudience = options.TokenEndpoint,
        IssuerSigningKey = new X509SecurityKey(certificate), ValidateIssuerSigningKey = true,
        RequireSignedTokens = true, RequireExpirationTime = true, ValidateLifetime = true,
        ValidAlgorithms = [SecurityAlgorithms.RsaSsaPssSha256], ClockSkew = TimeSpan.FromSeconds(30)
    }, out _);
    Console.WriteLine("OIDC_REAL_CERTIFICATE_PS256_SIGNATURE_PASS");
    using var handler = new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false, UseProxy = false };
    using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
    // Negative code probe: no interactive session, no access tokens expected. Provider processing order
    // can differ; invalid_grant alone is NOT proof of client authentication or successful OIDC login.
    using var form = new FormUrlEncodedContent(new Dictionary<string, string>
    {
        ["client_id"] = options.ClientId, ["grant_type"] = "authorization_code",
        ["code"] = "azzu-oidc-probe-not-a-real-authorization-code",
        ["redirect_uri"] = "https://banca.azzu.tech/api/v1/auth/callback",
        ["code_verifier"] = "azzu-probe-verifier-synthetic-not-a-real-flow-000001",
        ["client_assertion_type"] = OidcClientAssertion.AssertionType, ["client_assertion"] = assertion,
        ["scope"] = "openid profile"
    });
    using var response = await client.PostAsync(options.TokenEndpoint, form);
    var body = await response.Content.ReadAsStringAsync();
    if (response.StatusCode is not HttpStatusCode.BadRequest and not HttpStatusCode.Unauthorized)
        throw new InvalidOperationException("Unexpected negative authorization-code probe status.");
    using var json = JsonDocument.Parse(body);
    var error = json.RootElement.GetProperty("error").GetString();
    // Only approved protocol codes; never log error_description, request/assertion or response bodies.
    if (error == "invalid_grant") Console.WriteLine("OIDC_TOKEN_ENDPOINT_NEGATIVE_CODE_INVALID_GRANT; interactive login still unproven");
    else if (error == "invalid_client") throw new InvalidOperationException("OIDC client credential rejected.");
    else throw new InvalidOperationException("Negative code probe requires review; provider details withheld.");
}
catch (Exception error)
{
    Console.Error.WriteLine("OIDC_PROBE_FAILED:" + error.GetType().Name + "; no tokens or provider bodies logged");
    return 1;
}
return 0;
