namespace Azzu.WebBff.Api.Configuration;

public sealed class SessionOptions
{
    public const string SectionName = "Session";

    public int IdleTimeoutMinutes { get; init; } = 15;
    public bool RequireDistributedStoreInProduction { get; init; } = true;
    public string DistributedStoreProvider { get; init; } = "not-configured";
}

