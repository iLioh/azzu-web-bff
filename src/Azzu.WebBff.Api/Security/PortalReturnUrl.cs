namespace Azzu.WebBff.Api.Security;

public static class PortalReturnUrl
{
    public static string Normalize(string? value)
    {
        var path = value?.Split(['?', '#'], 2)[0] ?? string.Empty;
        if (path != "/portal" && !path.StartsWith("/portal/", StringComparison.Ordinal)) return "/portal/inicio";
        return path.All(character => char.IsAsciiLetterOrDigit(character) || character is '/' or '_' or '-')
            && !path.Contains("//", StringComparison.Ordinal) ? path : "/portal/inicio";
    }
}
