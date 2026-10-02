using Azzu.WebBff.Api.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
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
    // Internal write-only handler: ASP.NET Core otherwise renews an existing ITicketStore key on sign-in.
    public const string SessionIssuerScheme = "azzu-session-issuer";

    public static IServiceCollection AddAzzuAuthentication(this IServiceCollection services, IConfiguration configuration,
        System.Security.Cryptography.X509Certificates.X509Certificate2? oidcCertificate = null)
    {
        services.Configure<OidcOptions>(configuration.GetSection(OidcOptions.SectionName));
        services.Configure<BffSessionOptions>(configuration.GetSection(BffSessionOptions.SectionName));
        services.Configure<StepUpOptions>(configuration.GetSection(StepUpOptions.SectionName));

        var session = configuration.GetSection(BffSessionOptions.SectionName).Get<BffSessionOptions>() ?? new BffSessionOptions();
        var oidc = configuration.GetSection(OidcOptions.SectionName).Get<OidcOptions>() ?? new OidcOptions();
        var bankingTokens = configuration.GetSection(BankingTokenOptions.SectionName).Get<BankingTokenOptions>() ?? new();
        bankingTokens.Validate();
        services.Configure<BankingTokenOptions>(configuration.GetSection(BankingTokenOptions.SectionName));
        if (bankingTokens.Enabled && !oidc.IsConfigured)
            throw new InvalidOperationException("Delegated banking tokens require configured OIDC.");
        if (bankingTokens.Enabled && (bankingTokens.Audience == oidc.ClientId ||
            !Uri.TryCreate(oidc.TokenEndpoint, UriKind.Absolute, out var trustedEndpoint) || trustedEndpoint.Scheme != "https" ||
            trustedEndpoint.Host != new Uri(oidc.Authority).Host || !string.IsNullOrEmpty(trustedEndpoint.UserInfo) ||
            !string.IsNullOrEmpty(trustedEndpoint.Query) || !string.IsNullOrEmpty(trustedEndpoint.Fragment)))
            throw new InvalidOperationException("Delegated banking access requires a distinct API audience and an explicitly trusted OIDC token endpoint.");
        if (oidc.CredentialMode == "Certificate" && (!oidc.IsConfigured || oidcCertificate is null))
            throw new InvalidOperationException("OIDC certificate mode requires valid configuration and a loaded dedicated certificate.");

        Action<CookieAuthenticationOptions> configureCookie = options =>
            {
                options.Cookie.Name = SessionCookieName;
                options.Cookie.Path = "/";
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.SlidingExpiration = false;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(session.IdleTimeoutMinutes);
                options.Events.OnSigningIn = async context =>
                {
                    if (bankingTokens.Enabled && context.Options.SessionStore is null)
                        throw new InvalidOperationException("Delegated tokens must never be written into a browser cookie.");
                    // Reauthentication/step-up creates a fresh reference and revokes the previous local session.
                    var previous = await context.HttpContext.AuthenticateAsync(CookieScheme);
                    if (context.Options.SessionStore is not null && previous.Succeeded && previous.Properties is not null &&
                        previous.Properties.Items.TryGetValue(IServerSideTokenSessionStore.SessionKey, out var previousKey) &&
                        !string.IsNullOrEmpty(previousKey))
                        await context.Options.SessionStore.RemoveAsync(previousKey);
                };
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
                    return Results.Problem(statusCode: StatusCodes.Status401Unauthorized,
                        title: "The web session is missing or expired",
                        extensions: new Dictionary<string, object?> { ["code"] = "INVALID_SESSION_CONTEXT" })
                        .ExecuteAsync(context.HttpContext);
                };
                options.Events.OnRedirectToAccessDenied = static context =>
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    return Task.CompletedTask;
                };
            };

        var authentication = services.AddAuthentication(CookieScheme)
            .AddCookie(CookieScheme, configureCookie)
            .AddCookie(SessionIssuerScheme, configureCookie);
        services.Configure<CookieAuthenticationOptions>(CookieScheme, options => options.ForwardSignIn = SessionIssuerScheme);
        services.AddOptions<CookieAuthenticationOptions>(SessionIssuerScheme)
            .Configure<IDataProtectionProvider>((options, provider) =>
            {
                // Both handlers protect the same browser cookie; only the reader authenticates it.
                options.TicketDataFormat = new TicketDataFormat(provider.CreateProtector(
                    "Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware", CookieScheme, "v2"));
                // Only issuance ignores the incoming reference. Authentication/logout still read it normally.
                options.CookieManager = new FreshSessionCookieManager();
            });

        if (oidc.IsConfigured)
        {
            authentication.AddOpenIdConnect(OidcScheme, options =>
            {
                options.Authority = oidc.Authority;
                options.ClientId = oidc.ClientId;
                options.ClientSecret = oidc.ClientSecret;
                if (oidc.CredentialMode == "Certificate")
                {
                    options.Events.OnAuthorizationCodeReceived = async context =>
                    {
                        var metadata = await context.Options.ConfigurationManager!.GetConfigurationAsync(context.HttpContext.RequestAborted);
                        var request = context.TokenEndpointRequest ?? throw new InvalidOperationException("OIDC token request missing.");
                        request.ClientSecret = null;
                        request.SetParameter("client_assertion_type", OidcClientAssertion.AssertionType);
                        request.SetParameter("client_assertion", OidcClientAssertion.Create(oidc, oidcCertificate!, metadata.TokenEndpoint));
                    };
                }
                options.CallbackPath = oidc.CallbackPath;
                options.SignInScheme = CookieScheme;
                options.ResponseType = OpenIdConnectResponseType.Code;
                options.MapInboundClaims = false;
                options.UsePkce = true;
                // Enabled only with a mandatory server-side ticket store (see Program startup gate).
                options.SaveTokens = bankingTokens.Enabled;
                options.GetClaimsFromUserInfoEndpoint = false;
                options.RequireHttpsMetadata = true;
                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                if (bankingTokens.Enabled)
                {
                    options.Scope.Add("offline_access");
                    foreach (var scope in bankingTokens.Scopes) options.Scope.Add(scope);
                }
                options.Events.OnRedirectToIdentityProvider = context =>
                {
                    // .NET 8 forwards only known OIDC parameters automatically, not custom claims requests.
                    if (context.Properties.Parameters.TryGetValue(StepUpChallengeFactory.ClaimsParameter, out var value)
                        && value is string claims)
                    {
                        context.ProtocolMessage.SetParameter(StepUpChallengeFactory.ClaimsParameter, claims);
                    }

                    return Task.CompletedTask;
                };
                options.Events.OnTokenValidated = context =>
                {
                    if (!StepUpChallengeFactory.HasRequiredContext(context.Properties, context.Principal))
                    {
                        context.Fail("The required Conditional Access authentication context was not satisfied.");
                    }

                    return Task.CompletedTask;
                };
                options.Events.OnRemoteFailure = context =>
                {
                    // Do not propagate provider errors, codes or token values through the browser URL.
                    context.HandleResponse();
                    context.Response.Redirect("/login?reason=authentication-failed");
                    return Task.CompletedTask;
                };
                options.Events.OnTicketReceived = context =>
                {
                    if (bankingTokens.Enabled)
                    {
                        var properties = context.Properties;
                        if (properties is null || string.IsNullOrWhiteSpace(properties.GetTokenValue("access_token")) ||
                            string.IsNullOrWhiteSpace(properties.GetTokenValue("refresh_token")) ||
                            !string.Equals(properties.GetTokenValue("token_type"), "Bearer", StringComparison.OrdinalIgnoreCase) ||
                            !DateTimeOffset.TryParse(properties.GetTokenValue("expires_at"), out var expiry) || expiry <= DateTimeOffset.UtcNow)
                        {
                            context.HandleResponse();
                            context.Response.Redirect("/login?reason=authentication-failed");
                        }
                        else
                        {
                            // Only access/refresh tokens are needed for this transport. No ID token is ever an API bearer.
                            properties.StoreTokens(properties.GetTokens().Where(token => token.Name != "id_token").ToArray());
                        }
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
