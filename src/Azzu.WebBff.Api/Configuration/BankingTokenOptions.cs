namespace Azzu.WebBff.Api.Configuration;

public sealed class BankingTokenOptions
{
    public const string SectionName = "BankingTokens";
    public bool Enabled { get; init; }
    public string Audience { get; init; } = "";
    public string AppIdUri { get; init; } = "";
    public string BaseUrl { get; init; } = "";
    public string[] Scopes { get; init; } = [];
    public int RefreshBeforeExpirySeconds { get; init; } = 60;
    public int TimeoutSeconds { get; init; } = 10;

    public void Validate()
    {
        if (!Enabled) return;
        if (!Guid.TryParse(Audience, out var audience) || audience == Guid.Empty ||
            !Uri.TryCreate(AppIdUri, UriKind.Absolute, out var resource) ||
            resource.Scheme is not ("api" or "https") ||
            !string.IsNullOrEmpty(resource.UserInfo) || !string.IsNullOrEmpty(resource.Query) || !string.IsNullOrEmpty(resource.Fragment) ||
            !Uri.TryCreate(BaseUrl, UriKind.Absolute, out var backend) || backend.Scheme != "https" ||
            !string.IsNullOrEmpty(backend.UserInfo) || !string.IsNullOrEmpty(backend.Query) || !string.IsNullOrEmpty(backend.Fragment) ||
            !BaseUrl.EndsWith('/') ||
            RefreshBeforeExpirySeconds is < 10 or > 300 || TimeoutSeconds is < 1 or > 30 ||
            Scopes.Length == 0 || Scopes.Distinct(StringComparer.Ordinal).Count() != Scopes.Length ||
            Scopes.Any(scope => !scope.StartsWith(AppIdUri.TrimEnd('/') + "/", StringComparison.Ordinal) ||
                scope[(AppIdUri.TrimEnd('/').Length + 1)..] is "" or ".default" || scope.Any(char.IsWhiteSpace)))
            throw new InvalidOperationException("Banking delegated token configuration is incomplete or unsafe.");
    }
}
