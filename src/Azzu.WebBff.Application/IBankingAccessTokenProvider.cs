namespace Azzu.WebBff.Application;

// Server-side capability; never expose its return value through a web endpoint/DTO.
public interface IBankingAccessTokenProvider
{
    Task<string> GetAsync(IEnumerable<string> requiredScopes, CancellationToken cancellationToken);
}
