using Azzu.WebBff.Application;
using Azzu.WebBff.Contracts;
using Azzu.WebBff.Domain;

namespace Azzu.WebBff.Infrastructure;

public sealed class UnavailableChannelSecurityOperations : IChannelSecurityOperations
{
    private const string Detail = "The approved customer security adapter is not configured.";

    public Task<OperationAccepted> ChangeDigitalKeyAsync(
        CustomerOperationContext context,
        DigitalKeyChangeRequest request,
        CancellationToken cancellationToken) =>
        Task.FromException<OperationAccepted>(new BankingDependencyUnavailableException(Detail));

    public Task<OperationAccepted> RevokeOtherSessionsAsync(
        CustomerOperationContext context,
        CancellationToken cancellationToken) =>
        Task.FromException<OperationAccepted>(new BankingDependencyUnavailableException(Detail));
}

