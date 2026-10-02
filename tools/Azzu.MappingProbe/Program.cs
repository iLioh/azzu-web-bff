using System.Net;
using System.Net.Sockets;
using Azzu.WebBff.Domain;
using Azzu.WebBff.Infrastructure;

// Diagnostic executable, not a web server: no browser endpoints or login bypass.
try
{
    if (Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT") != "Development")
    {
        throw new InvalidOperationException("This diagnostic fixture executable is Development-only.");
    }
    var options = new IdentityMappingOptions
    {
        Enabled = true,
        Endpoint = "https://identity-mapping-onprem.itforbanking-dev.svc.cluster.local:7443/",
        TrustedIssuer = "https://db24bd50-f509-4173-9375-d30840ec6f39.ciamlogin.com/db24bd50-f509-4173-9375-d30840ec6f39/v2.0",
        TenantId = "db24bd50-f509-4173-9375-d30840ec6f39",
        TimeoutSeconds = 15,
        CertificateSource = "KeyVault",
        KeyVaultUri = "https://kv-azzu-web-dev-8466fe.vault.azure.net/",
        KeyVaultCertificateName = "azzu-web-bff-dev-mapping-mtls",
        KeyVaultCertificateVersion = "32d1a6918ebc48e68242d557c962ad57",
        WorkloadIdentityClientId = "6cdef73b-41a2-4aa5-b294-db6225286aed",
        ExpectedClientCertificateSha256 = "05204949158241B2181C4409A9E77F8D7EA75E6F6446A0A4083755465AD410A0",
        ExpectedRootCertificateSha256 = "A39C981E537F60D62EF541960183A397B320A4D71877D05D2E04E38F8115D78E",
        RootCertificatePath = "/public/ca.crt",
        // DEV CA has no CRL/OCSP. Does not disable hostname/chain/expiry validation.
        DisableRevocationCheckForDevelopment = true
    };
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(100));
    var vaultIps = await Dns.GetHostAddressesAsync(new Uri(options.KeyVaultUri).Host, deadline.Token);
    if (vaultIps.Length == 0 || vaultIps.Any(ip => ip.AddressFamily != AddressFamily.InterNetwork || ip.ToString() != "10.20.5.22"))
    {
        throw new InvalidOperationException("Private Key Vault DNS gate failed.");
    }

    Console.WriteLine("PRIVATE_VAULT_DNS_PASS");
    using var certificate = await KeyVaultMappingCertificateLoader.FromWorkloadIdentity(options).LoadAsync(options, deadline.Token);
    Console.WriteLine("WORKLOAD_IDENTITY_CERTIFICATE_LOAD_PASS; private key in ephemeral process memory only");
    using var transport = IdentityMappingTransport.Create(options, certificate);
    using var client = new HttpClient(transport) { BaseAddress = new Uri(options.Endpoint), Timeout = TimeSpan.FromSeconds(20) };
    foreach (var path in new[] { "/healthz", "/readyz" })
    {
        using var response = await client.GetAsync(path, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new InvalidOperationException("Mapping dependency probe returned non-success.");
        }
        Console.WriteLine($"MAPPING_MTLS_PASS:{path}:200");
    }

    using var withoutCertificate = IdentityMappingTransport.Create(options, certificate);
    ((SocketsHttpHandler)((DelegatingHandler)withoutCertificate).InnerHandler!).SslOptions.ClientCertificates!.Clear();
    using var anonymousClient = new HttpClient(withoutCertificate) { BaseAddress = client.BaseAddress, Timeout = TimeSpan.FromSeconds(15) };
    var rejectedWithoutCertificate = false;
    try
    {
        using var denied = await anonymousClient.GetAsync("/readyz", deadline.Token);
        rejectedWithoutCertificate = denied.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden;
    }
    catch (HttpRequestException)
    {
        rejectedWithoutCertificate = true;
    }
    if (!rejectedWithoutCertificate)
    {
        throw new InvalidOperationException("Mapping unexpectedly accepted request without client certificate.");
    }
    Console.WriteLine("MAPPING_WITHOUT_CLIENT_CERTIFICATE_REJECTED_PASS");

    // An explicitly supplied authorized DEV fixture, never a customer identity embedded in source.
    // This diagnostic validates the adapter/contract, not OIDC login or production authorization.
    var fixtureOid = Environment.GetEnvironmentVariable("AZZU_PROBE_ENTRA_OID");
    var fixtureCustomerId = Environment.GetEnvironmentVariable("AZZU_PROBE_EXPECTED_CUSTOMER_ID");
    if (!Guid.TryParse(fixtureOid, out var oid) || oid == Guid.Empty ||
        !Guid.TryParse(fixtureCustomerId, out var expectedCustomerId) || expectedCustomerId == Guid.Empty)
        throw new InvalidOperationException("Explicit authorized DEV fixture required.");
    var identity = new ExternalIdentity(Provider: "ENTRA_EXTERNAL_ID", Issuer: options.TrustedIssuer,
        SubjectType: "OID", Subject: oid.ToString(), TenantId: options.TenantId);
    var customerId = await new HttpCustomerIdentityMapping(client, options).ResolveCustomerIdAsync(identity, deadline.Token);
    if (!Guid.TryParse(customerId, out var resolvedCustomerId) || resolvedCustomerId != expectedCustomerId)
    {
        throw new InvalidOperationException("Mapping synthetic fixture resolution mismatch.");
    }
    Console.WriteLine("MAPPING_ADAPTER_SYNTHETIC_LINKED_FIXTURE_PASS; no OID/customer response logged");
    return 0;
}
catch (Exception error)
{
    // No request/response bodies, secret/PFX/token data, claims or exception detail in logs.
    Console.WriteLine("SAFE_PROBE_FAILURE:" + error.GetType().Name);
    return 1;
}
