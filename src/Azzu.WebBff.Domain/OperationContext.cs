namespace Azzu.WebBff.Domain;

public sealed record CustomerOperationContext(
    string CustomerId,
    string SubjectId,
    string Channel,
    string CorrelationId,
    string? SessionId,
    string? StepUpLevel,
    string? IdempotencyKey)
{
    public const string WebChannel = "web";
}

