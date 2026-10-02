using Microsoft.AspNetCore.Authentication.Cookies;

namespace Azzu.WebBff.Api.Security;

// Used exclusively by the internal sign-in scheme, never by authentication or logout.
// The framework must StoreAsync a fresh key instead of RenewAsync the revoked previous reference.
public sealed class FreshSessionCookieManager : ICookieManager
{
    private readonly ChunkingCookieManager _writer = new();

    public string? GetRequestCookie(HttpContext context, string key) => null;

    public void AppendResponseCookie(HttpContext context, string key, string? value, CookieOptions options) =>
        _writer.AppendResponseCookie(context, key, value, options);

    public void DeleteCookie(HttpContext context, string key, CookieOptions options) =>
        _writer.DeleteCookie(context, key, options);
}
