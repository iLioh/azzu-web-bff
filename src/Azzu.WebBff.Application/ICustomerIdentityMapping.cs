using Azzu.WebBff.Domain;

namespace Azzu.WebBff.Application;

public interface ICustomerIdentityMapping
{
    Task<string?> ResolveCustomerIdAsync(
        ExternalIdentity identity,
        CancellationToken cancellationToken);
}
