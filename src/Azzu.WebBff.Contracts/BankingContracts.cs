using System.ComponentModel.DataAnnotations;

namespace Azzu.WebBff.Contracts;

public sealed record AuthenticatedSession(
    string CustomerId,
    string DisplayName,
    DateTimeOffset ExpiresAtUtc,
    int IdleTimeoutSeconds,
    IReadOnlyCollection<string> AuthenticationMethods);

public sealed record CustomerProfile(
    string Email,
    string Phone,
    string Address);

public sealed record ProfileUpdateRequest(
    [property: EmailAddress, StringLength(254)] string Email,
    [property: RegularExpression("^9\\d{8}$")] string Phone,
    [property: Required, StringLength(200)] string Address);

public sealed record AccountDto(
    Guid Id,
    string Name,
    string Type,
    [property: RegularExpression("^\\d{4}$")] string LastDigits,
    decimal Balance,
    decimal Available,
    [property: RegularExpression("^(violet|blue)$")] string Accent,
    string Currency,
    string? Status = null);

public sealed record TransactionDto(
    Guid Id,
    Guid AccountId,
    string Counterparty,
    string Detail,
    DateTimeOffset Date,
    decimal Amount,
    [property: RegularExpression("^(income|expense)$")] string Category,
    string Initials,
    [property: RegularExpression("^(coral|purple|green)$")] string Color);

public sealed record NotificationDto(
    string Id,
    [property: RegularExpression("^(transfer|card|security)$")] string Type,
    string Title,
    string Detail,
    string Date,
    [property: Required, StringLength(200)] string Route,
    bool Unread);

public sealed record NotificationPreferencesRequest(
    bool Transfers,
    bool CardPurchases,
    bool Security,
    bool Marketing,
    [property: RegularExpression("^(email|push|both)$")] string Channel);

public sealed record TransferRequest(
    [property: Required] Guid SourceAccountId,
    [property: Required, RegularExpression("^\\d{8}$")] string RecipientDocument,
    [property: Required, StringLength(120)] string RecipientName,
    [property: Range(typeof(decimal), "0.01", "999999999.99")] decimal Amount,
    [property: StringLength(140)] string Description);

public sealed record PaymentRequest(
    [property: Required] Guid SourceAccountId,
    [property: Required, RegularExpression("^(Luz|Agua|Celular|Internet)$")] string Service,
    [property: Required, StringLength(40)] string CustomerCode,
    [property: Range(typeof(decimal), "0.01", "999999999.99")] decimal Amount);

public sealed record LoanSimulationRequest(
    [property: Range(typeof(decimal), "1", "999999999.99")] decimal Amount,
    [property: Range(1, 72)] int TermMonths,
    [property: Range(typeof(decimal), "1", "999999999.99")] decimal MonthlyIncome);

public sealed record LoanApplicationRequest(
    [property: Range(typeof(decimal), "1", "999999999.99")] decimal Amount,
    [property: Range(1, 72)] int TermMonths,
    [property: Range(typeof(decimal), "1", "999999999.99")] decimal MonthlyIncome,
    [property: Required] bool SimulationAccepted);

public sealed record LoanSimulationDto(
    decimal MonthlyPayment,
    decimal TotalPayment,
    decimal AnnualRate);

public sealed record ProcedureRequest(
    [property: Required, RegularExpression("^(bank-certificate|data-update|claim)$")] string Type,
    [property: Required, StringLength(1000)] string Detail);

public sealed record CardControlsRequest(
    [property: Required] Guid CardId,
    [property: Range(typeof(decimal), "0", "999999999.99")] decimal PurchaseLimit,
    bool OnlinePaymentsEnabled);

public sealed record CardTemporaryBlockRequest(
    [property: Required] bool Blocked);

public sealed record OperationAccepted(
    Guid Id,
    string Status,
    string Message);

public sealed record DigitalKeyChangeRequest(
    [property: Required, RegularExpression("^\\d{6}$")] string CurrentKey,
    [property: Required, RegularExpression("^\\d{6}$")] string NewKey);
