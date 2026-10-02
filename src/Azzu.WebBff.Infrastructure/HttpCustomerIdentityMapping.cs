using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Azzu.WebBff.Application;
using Azzu.WebBff.Domain;

namespace Azzu.WebBff.Infrastructure;

public sealed class HttpCustomerIdentityMapping(HttpClient client, IdentityMappingOptions options)
    : ICustomerIdentityMapping
{
    private const int MaximumResponseBytes = 16 * 1024;

    public async Task<string?> ResolveCustomerIdAsync(ExternalIdentity identity, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (identity.Provider != "ENTRA_EXTERNAL_ID" || identity.SubjectType != "OID"
            || !string.Equals(identity.Issuer, options.TrustedIssuer, StringComparison.Ordinal)
            || !string.Equals(identity.TenantId, options.TenantId, StringComparison.Ordinal)
            || !Guid.TryParse(identity.Subject, out var oid) || oid == Guid.Empty)
        {
            throw new InvalidSessionContextException("The session does not contain the configured customer identity context.");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(options.TimeoutSeconds));
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "/internal/identity/resolve")
            {
                Content = JsonContent.Create(identity)
            };
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (response.Content.Headers.ContentType?.MediaType is not ("application/json" or "application/problem+json"))
            {
                throw Unavailable();
            }

            using var body = await ReadBoundedJsonAsync(response.Content, timeout.Token);
            if (response.StatusCode == HttpStatusCode.OK)
            {
                if (!body.RootElement.TryGetProperty("status", out var status) || status.GetString() != "ACTIVE"
                    || !body.RootElement.TryGetProperty("customerId", out var customer)
                    || !Guid.TryParse(customer.GetString(), out var id) || id == Guid.Empty)
                {
                    throw Unavailable();
                }

                return id.ToString("D");
            }

            if (response.StatusCode == HttpStatusCode.Forbidden
                && body.RootElement.TryGetProperty("code", out var code))
            {
                if (code.GetString() == "CUSTOMER_IDENTITY_NOT_LINKED")
                {
                    return null;
                }

                if (code.GetString() == "CUSTOMER_ACCESS_DENIED")
                {
                    throw new CustomerAccessDeniedException("The banking customer is not allowed to operate.");
                }
            }

            // Caller authorization/configuration and dependency errors are not customer logout events.
            throw Unavailable();
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw Unavailable();
        }
        catch (Exception exception) when (exception is HttpRequestException or JsonException or InvalidOperationException or IOException)
        {
            // Never propagate the downstream body, URL, subject or TLS exception into browser/log detail.
            throw Unavailable();
        }
    }

    private static async Task<JsonDocument> ReadBoundedJsonAsync(HttpContent content, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength > MaximumResponseBytes)
        {
            throw Unavailable();
        }

        using var stream = await content.ReadAsStreamAsync(cancellationToken);
        var buffer = new byte[MaximumResponseBytes + 1];
        var length = 0;
        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(length), cancellationToken);
            if (read == 0)
            {
                return JsonDocument.Parse(buffer.AsMemory(0, length));
            }

            length += read;
            if (length > MaximumResponseBytes)
            {
                throw Unavailable();
            }
        }
    }

    private static CustomerIdentityMappingUnavailableException Unavailable() =>
        new("Customer identity mapping could not be completed safely.");
}
