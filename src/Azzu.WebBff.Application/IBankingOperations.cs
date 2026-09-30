using Azzu.WebBff.Contracts;
using Azzu.WebBff.Domain;

namespace Azzu.WebBff.Application;

public interface IBankingOperations
{
    Task<string> GetDisplayNameAsync(CustomerOperationContext context, CancellationToken cancellationToken);
    Task<CustomerProfile> GetProfileAsync(CustomerOperationContext context, CancellationToken cancellationToken);
    Task<OperationAccepted> UpdateProfileAsync(CustomerOperationContext context, ProfileUpdateRequest request, CancellationToken cancellationToken);
    Task<IReadOnlyCollection<AccountDto>> GetAccountsAsync(CustomerOperationContext context, CancellationToken cancellationToken);
    Task<IReadOnlyCollection<TransactionDto>> GetTransactionsAsync(CustomerOperationContext context, CancellationToken cancellationToken);
    Task<IReadOnlyCollection<NotificationDto>> GetNotificationsAsync(CustomerOperationContext context, CancellationToken cancellationToken);
    Task<OperationAccepted> MarkNotificationsReadAsync(CustomerOperationContext context, CancellationToken cancellationToken);
    Task<OperationAccepted> UpdateNotificationPreferencesAsync(CustomerOperationContext context, NotificationPreferencesRequest request, CancellationToken cancellationToken);
    Task<OperationAccepted> CreateTransferAsync(CustomerOperationContext context, TransferRequest request, CancellationToken cancellationToken);
    Task<OperationAccepted> CreatePaymentAsync(CustomerOperationContext context, PaymentRequest request, CancellationToken cancellationToken);
    Task<LoanSimulationDto> SimulateLoanAsync(CustomerOperationContext context, LoanSimulationRequest request, CancellationToken cancellationToken);
    Task<OperationAccepted> ApplyForLoanAsync(CustomerOperationContext context, LoanApplicationRequest request, CancellationToken cancellationToken);
    Task<OperationAccepted> SubmitProcedureAsync(CustomerOperationContext context, ProcedureRequest request, CancellationToken cancellationToken);
    Task<OperationAccepted> UpdateCardControlsAsync(CustomerOperationContext context, Guid cardId, CardControlsRequest request, CancellationToken cancellationToken);
    Task<OperationAccepted> SetCardTemporaryBlockAsync(CustomerOperationContext context, Guid cardId, CardTemporaryBlockRequest request, CancellationToken cancellationToken);
}
