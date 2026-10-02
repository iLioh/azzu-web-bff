using System.Net;
using System.Text;
using System.Text.Json;
using Azzu.WebBff.Application;
using Azzu.WebBff.Domain;
using Azzu.WebBff.Infrastructure;
using Xunit;

namespace Azzu.WebBff.Api.Tests;

public sealed class IdentityMappingAdapterTests
{
    private const string Issuer = "https://issuer.example.test/tenant/v2.0";
    private const string Tenant = "db24bd50-f509-4173-9375-d30840ec6f39";
    private const string ObjectId = "00000000-0000-0000-0000-000000000001";
    private const string CustomerId = "11111111-1111-1111-1111-111111111111";
    private static readonly string[] RequestFields = ["issuer", "provider", "subject", "subjectType", "tenantId"];
    private static ExternalIdentity Identity => new("ENTRA_EXTERNAL_ID", Issuer, "OID", ObjectId, Tenant);

    [Fact]
    public async Task SendsExactMappingContractWithoutBrowserCredentials()
    {
        using var handler = new StubHandler(async (request, cancellation) =>
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("/internal/identity/resolve", request.RequestUri!.AbsolutePath);
            Assert.Null(request.Headers.Authorization);
            Assert.False(request.Headers.Contains("Cookie"));
            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellation));
            var fields = body.RootElement.EnumerateObject().Select(property => property.Name).Order().ToArray();
            Assert.Equal(RequestFields, fields);
            Assert.Equal(ObjectId, body.RootElement.GetProperty("subject").GetString());
            Assert.Equal("OID", body.RootElement.GetProperty("subjectType").GetString());
            Assert.Equal(Tenant, body.RootElement.GetProperty("tenantId").GetString());
            return Json(HttpStatusCode.OK, $"{{\"customerId\":\"{CustomerId}\",\"status\":\"ACTIVE\"}}");
        });
        using var client = Client(handler);
        Assert.Equal(CustomerId, await Adapter(client).ResolveCustomerIdAsync(Identity, CancellationToken.None));
        Assert.Equal(1, handler.Calls);
    }

    [Theory]
    [InlineData("customerId", "ACTIVE")]
    [InlineData("00000000-0000-0000-0000-000000000000", "ACTIVE")]
    [InlineData(CustomerId, "BLOCKED")]
    [InlineData(CustomerId, "active")]
    public async Task RejectsInvalidOrInactiveSuccessfulResponse(string customer, string status)
    {
        using var handler = new StubHandler((_, _) => Task.FromResult(Json(HttpStatusCode.OK,
            $"{{\"customerId\":\"{customer}\",\"status\":\"{status}\"}}")));
        using var client = Client(handler);
        await Assert.ThrowsAsync<CustomerIdentityMappingUnavailableException>(() =>
            Adapter(client).ResolveCustomerIdAsync(Identity, CancellationToken.None));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("not-json")]
    [InlineData("[]")]
    [InlineData("{\"status\":3,\"customerId\":false}")]
    public async Task MalformedResponseFailsClosed(string body)
    {
        using var handler = new StubHandler((_, _) => Task.FromResult(Json(HttpStatusCode.OK, body)));
        using var client = Client(handler);
        await Assert.ThrowsAsync<CustomerIdentityMappingUnavailableException>(() =>
            Adapter(client).ResolveCustomerIdAsync(Identity, CancellationToken.None));
    }

    [Fact]
    public async Task UnlinkedIdentityIsNotAServiceFailure()
    {
        using var handler = new StubHandler((_, _) => Task.FromResult(Json(HttpStatusCode.Forbidden,
            "{\"code\":\"CUSTOMER_IDENTITY_NOT_LINKED\"}")));
        using var client = Client(handler);
        Assert.Null(await Adapter(client).ResolveCustomerIdAsync(Identity, CancellationToken.None));
    }

    [Fact]
    public async Task BlockedCustomerIsNotReportedAsMissingLink()
    {
        using var handler = new StubHandler((_, _) => Task.FromResult(Json(HttpStatusCode.Forbidden,
            "{\"code\":\"CUSTOMER_ACCESS_DENIED\"}")));
        using var client = Client(handler);
        await Assert.ThrowsAsync<CustomerAccessDeniedException>(() =>
            Adapter(client).ResolveCustomerIdAsync(Identity, CancellationToken.None));
    }

    [Theory]
    [InlineData(403, "CALLER_NOT_AUTHORIZED")]
    [InlineData(400, "INVALID_IDENTITY_CONTEXT")]
    [InlineData(429, "RATE_LIMIT_EXCEEDED")]
    [InlineData(503, "CUSTOMER_IDENTITY_MAPPING_UNAVAILABLE")]
    [InlineData(401, "INVALID_TOKEN")]
    [InlineData(302, "redirect")]
    public async Task OperationalErrorsAreUnavailableWithoutRetry(int status, string code)
    {
        using var handler = new StubHandler((_, _) => Task.FromResult(Json((HttpStatusCode)status,
            $"{{\"code\":\"{code}\",\"detail\":\"do not leak this\"}}")));
        using var client = Client(handler);
        var exception = await Assert.ThrowsAsync<CustomerIdentityMappingUnavailableException>(() =>
            Adapter(client).ResolveCustomerIdAsync(Identity, CancellationToken.None));
        Assert.DoesNotContain("do not leak", exception.Message, StringComparison.Ordinal);
        Assert.Null(exception.InnerException);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task OversizedResponseFailsClosed()
    {
        using var handler = new StubHandler((_, _) => Task.FromResult(Json(HttpStatusCode.OK, new string('x', 17000))));
        using var client = Client(handler);
        await Assert.ThrowsAsync<CustomerIdentityMappingUnavailableException>(() =>
            Adapter(client).ResolveCustomerIdAsync(Identity, CancellationToken.None));
    }

    [Fact]
    public async Task NonJsonContentFailsClosed()
    {
        using var handler = new StubHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("<html>unexpected gateway</html>")
        }));
        using var client = Client(handler);
        await Assert.ThrowsAsync<CustomerIdentityMappingUnavailableException>(() =>
            Adapter(client).ResolveCustomerIdAsync(Identity, CancellationToken.None));
    }

    [Fact]
    public async Task NetworkFailureDoesNotExposeSensitiveException()
    {
        using var handler = new StubHandler((_, _) => throw new HttpRequestException("private network detail"));
        using var client = Client(handler);
        var exception = await Assert.ThrowsAsync<CustomerIdentityMappingUnavailableException>(() =>
            Adapter(client).ResolveCustomerIdAsync(Identity, CancellationToken.None));
        Assert.DoesNotContain("private network", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TimeoutBecomesAvailabilityError()
    {
        using var handler = new StubHandler(async (_, cancellation) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellation);
            return Json(HttpStatusCode.OK, "{}");
        });
        using var client = Client(handler);
        var options = Options();
        options.TimeoutSeconds = 1;
        await Assert.ThrowsAsync<CustomerIdentityMappingUnavailableException>(() =>
            new HttpCustomerIdentityMapping(client, options).ResolveCustomerIdAsync(Identity, CancellationToken.None));
    }

    [Fact]
    public async Task CallerCancellationIsNotConvertedIntoMappingOutage()
    {
        using var handler = new StubHandler((_, cancellation) => Task.FromCanceled<HttpResponseMessage>(cancellation));
        using var client = Client(handler);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Adapter(client).ResolveCustomerIdAsync(Identity, cancellation.Token));
    }

    [Theory]
    [InlineData("KEYCLOAK", Issuer, "OID", ObjectId, Tenant)]
    [InlineData("ENTRA_EXTERNAL_ID", "https://untrusted.example", "OID", ObjectId, Tenant)]
    [InlineData("ENTRA_EXTERNAL_ID", Issuer, "SUB", ObjectId, Tenant)]
    [InlineData("ENTRA_EXTERNAL_ID", Issuer, "OID", "74851236", Tenant)]
    [InlineData("ENTRA_EXTERNAL_ID", Issuer, "OID", ObjectId, "other-tenant")]
    public async Task InvalidIdentityIsRejectedBeforeNetwork(string provider, string issuer, string type, string subject, string tenant)
    {
        using var handler = new StubHandler((_, _) => throw new InvalidOperationException("Must not send"));
        using var client = Client(handler);
        await Assert.ThrowsAsync<InvalidSessionContextException>(() => Adapter(client).ResolveCustomerIdAsync(
            new ExternalIdentity(provider, issuer, type, subject, tenant), CancellationToken.None));
        Assert.Equal(0, handler.Calls);
    }

    [Theory]
    [InlineData("http://mapping.example/")]
    [InlineData("https://mapping.example/path")]
    [InlineData("https://user:password@mapping.example/")]
    public void ConfigurationRejectsUnsafeEndpoint(string endpoint)
    {
        var options = Options();
        options.Endpoint = endpoint;
        Assert.Throws<InvalidOperationException>(options.Validate);
    }

    private static IdentityMappingOptions Options() => new()
    {
        TrustedIssuer = Issuer,
        TenantId = Tenant,
        Endpoint = "https://mapping.example/",
        ClientCertificatePath = "mounted/client.crt",
        ClientKeyPath = "mounted/client.key",
        RootCertificatePath = "mounted/ca.crt"
    };

    private static HttpCustomerIdentityMapping Adapter(HttpClient client) => new(client, Options());
    private static HttpClient Client(HttpMessageHandler handler) => new(handler)
    {
        BaseAddress = new Uri("https://mapping.example/"),
        Timeout = Timeout.InfiniteTimeSpan
    };

    private static HttpResponseMessage Json(HttpStatusCode status, string body) => new(status)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json")
    };

    private sealed class StubHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond)
        : HttpMessageHandler
    {
        public int Calls { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return respond(request, cancellationToken);
        }
    }
}
