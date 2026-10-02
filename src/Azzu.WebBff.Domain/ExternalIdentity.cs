namespace Azzu.WebBff.Domain;

public sealed record ExternalIdentity(
    string Provider,
    string Issuer,
    string SubjectType,
    string Subject,
    string? TenantId);
