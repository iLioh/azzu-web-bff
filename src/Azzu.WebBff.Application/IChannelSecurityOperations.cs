using Azzu.WebBff.Contracts;
using Azzu.WebBff.Domain;

namespace Azzu.WebBff.Application;

public interface IChannelSecurityOperations
{
    Task<OperationAccepted> ChangeDigitalKeyAsync(
        CustomerOperationContext context,
        DigitalKeyChangeRequest request,
        CancellationToken cancellationToken);

    Task<OperationAccepted> RevokeOtherSessionsAsync(
        CustomerOperationContext context,
        CancellationToken cancellationToken);
}

