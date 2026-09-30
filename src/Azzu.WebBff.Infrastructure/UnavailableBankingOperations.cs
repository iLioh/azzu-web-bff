using Azzu.WebBff.Application;
using Azzu.WebBff.Contracts;
using Azzu.WebBff.Domain;

namespace Azzu.WebBff.Infrastructure;

public sealed class UnavailableBankingOperations : IBankingOperations
{
    private const string Detail = "The approved Banking Services adapter is not configured.";

    public Task<string> GetDisplayNameAsync(CustomerOperationContext context, CancellationToken cancellationToken) =>
        Task.FromException<string>(new BankingDependencyUnavailableException(Detail));

    public Task<CustomerProfile> GetProfileAsync(CustomerOperationContext context, CancellationToken cancellationToken) =>
        Task.FromException<CustomerProfile>(new BankingDependencyUnavailableException(Detail));

    public Task<OperationAccepted> UpdateProfileAsync(CustomerOperationContext context, ProfileUpdateRequest request, CancellationToken cancellationToken) =>
        Task.FromException<OperationAccepted>(new BankingDependencyUnavailableException(Detail));

    public Task<IReadOnlyCollection<AccountDto>> GetAccountsAsync(CustomerOperationContext context, CancellationToken cancellationToken) =>
        Task.FromException<IReadOnlyCollection<AccountDto>>(new BankingDependencyUnavailableException(Detail));

    public Task<IReadOnlyCollection<TransactionDto>> GetTransactionsAsync(CustomerOperationContext context, CancellationToken cancellationToken) =>
        Task.FromException<IReadOnlyCollection<TransactionDto>>(new BankingDependencyUnavailableException(Detail));

    public Task<IReadOnlyCollection<NotificationDto>> GetNotificationsAsync(CustomerOperationContext context, CancellationToken cancellationToken) =>
        Task.FromException<IReadOnlyCollection<NotificationDto>>(new BankingDependencyUnavailableException(Detail));

    public Task<OperationAccepted> MarkNotificationsReadAsync(CustomerOperationContext context, CancellationToken cancellationToken) =>
        Task.FromException<OperationAccepted>(new BankingDependencyUnavailableException(Detail));

    public Task<OperationAccepted> UpdateNotificationPreferencesAsync(CustomerOperationContext context, NotificationPreferencesRequest request, CancellationToken cancellationToken) =>
        Task.FromException<OperationAccepted>(new BankingDependencyUnavailableException(Detail));

    public Task<OperationAccepted> CreateTransferAsync(CustomerOperationContext context, TransferRequest request, CancellationToken cancellationToken) =>
        Task.FromException<OperationAccepted>(new BankingDependencyUnavailableException(Detail));

    public Task<OperationAccepted> CreatePaymentAsync(CustomerOperationContext context, PaymentRequest request, CancellationToken cancellationToken) =>
        Task.FromException<OperationAccepted>(new BankingDependencyUnavailableException(Detail));

    public Task<LoanSimulationDto> SimulateLoanAsync(CustomerOperationContext context, LoanSimulationRequest request, CancellationToken cancellationToken) =>
        Task.FromException<LoanSimulationDto>(new BankingDependencyUnavailableException(Detail));

    public Task<OperationAccepted> ApplyForLoanAsync(CustomerOperationContext context, LoanApplicationRequest request, CancellationToken cancellationToken) =>
        Task.FromException<OperationAccepted>(new BankingDependencyUnavailableException(Detail));

    public Task<OperationAccepted> SubmitProcedureAsync(CustomerOperationContext context, ProcedureRequest request, CancellationToken cancellationToken) =>
        Task.FromException<OperationAccepted>(new BankingDependencyUnavailableException(Detail));

    public Task<OperationAccepted> UpdateCardControlsAsync(CustomerOperationContext context, Guid cardId, CardControlsRequest request, CancellationToken cancellationToken) =>
        Task.FromException<OperationAccepted>(new BankingDependencyUnavailableException(Detail));

    public Task<OperationAccepted> SetCardTemporaryBlockAsync(CustomerOperationContext context, Guid cardId, CardTemporaryBlockRequest request, CancellationToken cancellationToken) =>
        Task.FromException<OperationAccepted>(new BankingDependencyUnavailableException(Detail));
}
