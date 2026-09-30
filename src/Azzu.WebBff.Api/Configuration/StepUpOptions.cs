namespace Azzu.WebBff.Api.Configuration;

public sealed class StepUpOptions
{
    public const string SectionName = "StepUp";

    public Dictionary<string, string> AuthenticationContexts { get; init; } =
        new(StringComparer.OrdinalIgnoreCase);
}
