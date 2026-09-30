using Azzu.WebBff.Api.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using BffSessionOptions = Azzu.WebBff.Api.Configuration.SessionOptions;

namespace Azzu.WebBff.Api.Security;

public static class AuthenticationExtensions
{
    public const string CookieScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    public const string OidcScheme = "azzu-oidc";
    public const string SessionCookieName = "__Host-AzzuSession";

    public static IServiceCollection AddAzzuAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<OidcOptions>(configuration.GetSection(OidcOptions.SectionName));
        services.Configure<BffSessionOptions>(configuration.GetSection(BffSessionOptions.SectionName));
        services.Configure<StepUpOptions>(configuration.GetSection(StepUpOptions.SectionName));

        var session = configuration.GetSection(BffSessionOptions.SectionName).Get<BffSessionOptions>() ?? new BffSessionOptions();
        var oidc = configuration.GetSection(OidcOptions.SectionName).Get<OidcOptions>() ?? new OidcOptions();

        var authentication = services
            .AddAuthentication(CookieScheme)
            .AddCookie(CookieScheme, options =>
            {
                options.Cookie.Name = SessionCookieName;
                options.Cookie.Path = "/";
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.SlidingExpiration = false;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(session.IdleTimeoutMinutes);
                options.Events.OnRedirectToLogin = context =>
                {
                    context.Response.Cookies.Delete(SessionCookieName, new CookieOptions
                    {
                        Path = "/",
                        HttpOnly = true,
                        Secure = true,
                        SameSite = SameSiteMode.Lax
                    });
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return Task.CompletedTask;
                };
                options.Events.OnRedirectToAccessDenied = static context =>
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    return Task.CompletedTask;
                };
            });

        if (oidc.IsConfigured)
        {
            authentication.AddOpenIdConnect(OidcScheme, options =>
            {
                options.Authority = oidc.Authority;
                options.ClientId = oidc.ClientId;
                options.ClientSecret = oidc.ClientSecret;
                options.CallbackPath = oidc.CallbackPath;
                options.SignInScheme = CookieScheme;
                options.ResponseType = OpenIdConnectResponseType.Code;
                options.MapInboundClaims = false;
                options.UsePkce = true;
                options.SaveTokens = false;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.RequireHttpsMetadata = true;
                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Events.OnTokenValidated = context =>
                {
                    if (!StepUpChallengeFactory.HasRequiredContext(context.Properties, context.Principal))
                    {
                        context.Fail("The required Conditional Access authentication context was not satisfied.");
                    }

                    return Task.CompletedTask;
                };
            });
        }

        services.AddAuthorization(options =>
        {
            options.FallbackPolicy = new AuthorizationPolicyBuilder()
                .AddAuthenticationSchemes(CookieScheme)
                .RequireAuthenticatedUser()
                .Build();
        });

        return services;
    }

    public static bool IsOidcConfigured(this IOptions<OidcOptions> options) => options.Value.IsConfigured;

    public static void ValidateProductionSessionConfiguration(
        this IHostEnvironment environment,
        IProductionSessionSecurityReadiness readiness)
    {
        if (!environment.IsProduction())
        {
            return;
        }

        if (!readiness.HasDistributedServerSideSessionStore || !readiness.HasSharedDataProtectionKeyStore)
        {
            throw new InvalidOperationException(
                "Production requires a configured distributed session store and shared Data Protection key store.");
        }
    }
}
