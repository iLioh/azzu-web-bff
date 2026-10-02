using Azzu.WebBff.Application;

namespace Azzu.WebBff.Infrastructure;

// Transport only. The typed IBankingOperations adapter must await Sara's approved contract.
public sealed class DelegatedBankingClient(HttpClient client, IBankingAccessTokenProvider tokens, BankingApiTransportOptions options)
{
    public async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, IEnumerable<string> requiredScopes,
        CancellationToken cancellationToken)
    {
        if (!options.Enabled) throw new BankingDependencyUnavailableException("Banking API is not configured.");
        var origin = new Uri(options.BaseUrl);
        if (request.RequestUri is null) throw new BankingDependencyUnavailableException("Banking API destination is required.");
        var destination = request.RequestUri.IsAbsoluteUri ? request.RequestUri : new Uri(origin, request.RequestUri);
        if (destination.Scheme != "https" || destination.Authority != origin.Authority ||
            !destination.AbsolutePath.StartsWith(origin.AbsolutePath.TrimEnd('/') + "/", StringComparison.Ordinal) ||
            !string.IsNullOrEmpty(destination.UserInfo) || !string.IsNullOrEmpty(destination.Fragment))
            throw new BankingDependencyUnavailableException("Banking API destination is not allowed.");
        if (request.Headers.Authorization is not null || request.Headers.Contains("Cookie") || request.Headers.Contains("X-Customer-Id"))
            throw new BankingDependencyUnavailableException("Untrusted banking request credentials are not permitted.");
        request.RequestUri = destination;
        request.Headers.Authorization = new("Bearer", await tokens.GetAsync(requiredScopes, cancellationToken));
        try { return await client.SendAsync(request, cancellationToken); }
        catch (HttpRequestException) { throw new BankingDependencyUnavailableException("Banking API is temporarily unavailable."); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { throw new BankingDependencyUnavailableException("Banking API timed out."); }
        finally { request.Headers.Authorization = null; }
        // No retry on 401/mutations; error normalization belongs to the typed adapter, not a generic proxy.
    }
}
