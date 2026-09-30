using Azzu.WebBff.Application;
using Azzu.WebBff.Domain;

namespace Azzu.WebBff.Infrastructure;

public sealed class UnavailableCustomerIdentityMapping : ICustomerIdentityMapping
{
    public Task<string?> ResolveCustomerIdAsync(
        ExternalIdentity identity,
        CancellationToken cancellationToken) =>
        throw new CustomerIdentityMappingUnavailableException(
            "The banking customer identity mapping service is not configured.");
}
