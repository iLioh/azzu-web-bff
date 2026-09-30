using System.Security.Claims;
using Azzu.WebBff.Api.Configuration;
using Azzu.WebBff.Api.Security;
using Azzu.WebBff.Application;
using Azzu.WebBff.Contracts;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Extensions.Options;
using BffSessionOptions = Azzu.WebBff.Api.Configuration.SessionOptions;

namespace Azzu.WebBff.Api.Endpoints;

public static class WebBffEndpointExtensions
{
    public static void MapWebBffEndpoints(this WebApplication app)
    {
        app.MapGet("/health/live", () => Results.Ok(new { status = "live" })).AllowAnonymous();
        app.MapGet("/health/ready", () => Results.Ok(new { status = "ready" })).AllowAnonymous();

        var api = app.MapGroup("/api/v1");
        MapAuthenticationRoutes(api);

        var authenticated = api
            .RequireAuthorization()
            .AddEndpointFilter<AntiforgeryValidationFilter>()
            .AddEndpointFilter<RequestValidationFilter>();

        MapAuthenticatedRoutes(authenticated);
    }

    private static void MapAuthenticationRoutes(RouteGroupBuilder api)
    {
        api.MapGet("/auth/login", (
            IOptions<OidcOptions> oidcOptions) =>
        {
            if (!oidcOptions.IsOidcConfigured())
            {
                return OidcUnavailable();
            }

            var properties = new AuthenticationProperties
            {
                RedirectUri = "/api/v1/auth/session"
            };
            return Results.Challenge(properties, [AuthenticationExtensions.OidcScheme]);
        }).AllowAnonymous();

        api.MapGet("/auth/step-up", (
            string? operation,
            IOptions<OidcOptions> oidcOptions,
            StepUpChallengeFactory challengeFactory) =>
        {
            if (!oidcOptions.IsOidcConfigured())
            {
                return OidcUnavailable();
            }

            var properties = challengeFactory.Create(
                string.IsNullOrWhiteSpace(operation) ? StepUpChallengeFactory.DefaultOperation : operation,
                "/api/v1/auth/session");
            return Results.Challenge(properties, [AuthenticationExtensions.OidcScheme]);
        }).RequireAuthorization();
    }

    private static void MapAuthenticatedRoutes(RouteGroupBuilder api)
    {
        api.MapGet("/auth/session", async (
            HttpContext context,
            IAntiforgery antiforgery,
            CustomerOperationContextFactory contextFactory,
            IOptions<BffSessionOptions> sessionOptions,
            CancellationToken cancellationToken) =>
        {
            var authentication = context.Features.Get<IAuthenticateResultFeature>()?.AuthenticateResult
                ?? await context.AuthenticateAsync();
            var expiresAtUtc = authentication.Properties?.ExpiresUtc;
            if (!authentication.Succeeded
                || expiresAtUtc is null
                || expiresAtUtc <= DateTimeOffset.UtcNow)
            {
                throw new InvalidSessionContextException("The web session ticket is missing or expired.");
            }

            var antiforgeryTokens = antiforgery.GetAndStoreTokens(context);
            if (string.IsNullOrWhiteSpace(antiforgeryTokens.RequestToken))
            {
                throw new InvalidOperationException("An antiforgery request token could not be issued.");
            }

            context.Response.Cookies.Append("XSRF-TOKEN", antiforgeryTokens.RequestToken, new CookieOptions
            {
                Path = "/",
                HttpOnly = false,
                Secure = true,
                SameSite = SameSiteMode.Lax
            });
            context.Response.Headers.CacheControl = "no-store";

            var methods = context.User.FindAll("amr")
                .Select(claim => claim.Value)
                .Distinct(StringComparer.Ordinal)
                .ToArray();

            var operationContext = await contextFactory.CreateAsync(context, cancellationToken);
            return TypedResults.Ok(new AuthenticatedSession(
                operationContext.CustomerId,
                CustomerOperationContextFactory.GetDisplayName(context),
                expiresAtUtc.Value,
                checked(sessionOptions.Value.IdleTimeoutMinutes * 60),
                methods));
        });

        api.MapPost("/auth/logout", async (HttpContext context) =>
        {
            await context.SignOutAsync(AuthenticationExtensions.CookieScheme);
            context.Response.Headers.CacheControl = "no-store";
            return Results.NoContent();
        });

        api.MapPut("/auth/digital-key", async (
            HttpContext context,
            DigitalKeyChangeRequest request,
            IChannelSecurityOperations operations,
            CustomerOperationContextFactory contextFactory,
            CancellationToken cancellationToken) =>
        {
            var operation = await operations.ChangeDigitalKeyAsync(
                await contextFactory.CreateAsync(context, cancellationToken),
                request,
                cancellationToken);
            return TypedResults.Accepted($"/api/v1/operations/{operation.Id}", operation);
        }).RequireRateLimiting("sensitive");

        api.MapPost("/auth/sessions/revoke-others", async (
            HttpContext context,
            IChannelSecurityOperations operations,
            CustomerOperationContextFactory contextFactory,
            CancellationToken cancellationToken) =>
        {
            var operation = await operations.RevokeOtherSessionsAsync(
                await contextFactory.CreateAsync(context, cancellationToken),
                cancellationToken);
            return TypedResults.Accepted($"/api/v1/operations/{operation.Id}", operation);
        }).RequireRateLimiting("sensitive");

        api.MapGet("/customers/me/display-name", async (
            HttpContext context,
            IBankingOperations operations,
            CustomerOperationContextFactory contextFactory,
            CancellationToken cancellationToken) =>
            TypedResults.Ok(await operations.GetDisplayNameAsync(
                await contextFactory.CreateAsync(context, cancellationToken),
                cancellationToken)));

        api.MapPut("/customers/me/profile", async (
            HttpContext context,
            ProfileUpdateRequest request,
            IBankingOperations operations,
            CustomerOperationContextFactory contextFactory,
            CancellationToken cancellationToken) =>
        {
            var operation = await operations.UpdateProfileAsync(
                await contextFactory.CreateAsync(context, cancellationToken),
                request,
                cancellationToken);
            return TypedResults.Accepted($"/api/v1/operations/{operation.Id}", operation);
        });

        api.MapGet("/accounts", async (
            HttpContext context,
            IBankingOperations operations,
            CustomerOperationContextFactory contextFactory,
            CancellationToken cancellationToken) =>
            TypedResults.Ok(await operations.GetAccountsAsync(
                await contextFactory.CreateAsync(context, cancellationToken),
                cancellationToken)));

        api.MapGet("/transactions", async (
            HttpContext context,
            IBankingOperations operations,
            CustomerOperationContextFactory contextFactory,
            CancellationToken cancellationToken) =>
            TypedResults.Ok(await operations.GetTransactionsAsync(
                await contextFactory.CreateAsync(context, cancellationToken),
                cancellationToken)));

        api.MapGet("/notifications", async (
            HttpContext context,
            IBankingOperations operations,
            CustomerOperationContextFactory contextFactory,
            CancellationToken cancellationToken) =>
            TypedResults.Ok(await operations.GetNotificationsAsync(
                await contextFactory.CreateAsync(context, cancellationToken),
                cancellationToken)));

        api.MapPost("/notifications/read", async (
            HttpContext context,
            IBankingOperations operations,
            CustomerOperationContextFactory contextFactory,
            CancellationToken cancellationToken) =>
        {
            var operation = await operations.MarkNotificationsReadAsync(
                await contextFactory.CreateAsync(context, cancellationToken),
                cancellationToken);
            return TypedResults.Accepted($"/api/v1/operations/{operation.Id}", operation);
        });

        api.MapPut("/notifications/preferences", async (
            HttpContext context,
            NotificationPreferencesRequest request,
            IBankingOperations operations,
            CustomerOperationContextFactory contextFactory,
            CancellationToken cancellationToken) =>
        {
            var operation = await operations.UpdateNotificationPreferencesAsync(
                await contextFactory.CreateAsync(context, cancellationToken),
                request,
                cancellationToken);
            return TypedResults.Accepted($"/api/v1/operations/{operation.Id}", operation);
        });

        api.MapPost("/transfers", async (
            HttpContext context,
            TransferRequest request,
            IBankingOperations operations,
            CustomerOperationContextFactory contextFactory,
            CancellationToken cancellationToken) =>
        {
            var operation = await operations.CreateTransferAsync(
                await contextFactory.CreateAsync(context, cancellationToken),
                request,
                cancellationToken);
            return TypedResults.Accepted($"/api/v1/operations/{operation.Id}", operation);
        }).AddEndpointFilter<IdempotencyKeyFilter>().RequireRateLimiting("sensitive");

        api.MapPost("/payments", async (
            HttpContext context,
            PaymentRequest request,
            IBankingOperations operations,
            CustomerOperationContextFactory contextFactory,
            CancellationToken cancellationToken) =>
        {
            var operation = await operations.CreatePaymentAsync(
                await contextFactory.CreateAsync(context, cancellationToken),
                request,
                cancellationToken);
            return TypedResults.Accepted($"/api/v1/operations/{operation.Id}", operation);
        }).AddEndpointFilter<IdempotencyKeyFilter>().RequireRateLimiting("sensitive");

        api.MapPost("/loans/simulations", async (
            HttpContext context,
            LoanSimulationRequest request,
            IBankingOperations operations,
            CustomerOperationContextFactory contextFactory,
            CancellationToken cancellationToken) =>
            TypedResults.Ok(await operations.SimulateLoanAsync(
                await contextFactory.CreateAsync(context, cancellationToken),
                request,
                cancellationToken)));

        api.MapPost("/loans/applications", async (
            HttpContext context,
            LoanApplicationRequest request,
            IBankingOperations operations,
            CustomerOperationContextFactory contextFactory,
            CancellationToken cancellationToken) =>
        {
            var operation = await operations.ApplyForLoanAsync(
                await contextFactory.CreateAsync(context, cancellationToken),
                request,
                cancellationToken);
            return TypedResults.Accepted($"/api/v1/operations/{operation.Id}", operation);
        }).AddEndpointFilter<IdempotencyKeyFilter>().RequireRateLimiting("sensitive");

        api.MapPost("/procedures", async (
            HttpContext context,
            ProcedureRequest request,
            IBankingOperations operations,
            CustomerOperationContextFactory contextFactory,
            CancellationToken cancellationToken) =>
        {
            var operation = await operations.SubmitProcedureAsync(
                await contextFactory.CreateAsync(context, cancellationToken),
                request,
                cancellationToken);
            return TypedResults.Accepted($"/api/v1/operations/{operation.Id}", operation);
        });

        api.MapPut("/cards/{cardId:guid}/controls", async (
            HttpContext context,
            Guid cardId,
            CardControlsRequest request,
            IBankingOperations operations,
            CustomerOperationContextFactory contextFactory,
            CancellationToken cancellationToken) =>
        {
            if (cardId != request.CardId)
            {
                return Results.ValidationProblem(
                    new Dictionary<string, string[]>
                    {
                        ["cardId"] = ["The path cardId must match the request cardId."]
                    },
                    statusCode: StatusCodes.Status400BadRequest,
                    title: "Request validation failed",
                    type: "https://azzu.tech/problems/request-validation-failed");
            }

            var operation = await operations.UpdateCardControlsAsync(
                await contextFactory.CreateAsync(context, cancellationToken),
                cardId,
                request,
                cancellationToken);
            return TypedResults.Accepted($"/api/v1/operations/{operation.Id}", operation);
        }).AddEndpointFilter<IdempotencyKeyFilter>().RequireRateLimiting("sensitive");

        api.MapPut("/cards/{cardId:guid}/temporary-block", async (
            HttpContext context,
            Guid cardId,
            CardTemporaryBlockRequest request,
            IBankingOperations operations,
            CustomerOperationContextFactory contextFactory,
            CancellationToken cancellationToken) =>
        {
            var operation = await operations.SetCardTemporaryBlockAsync(
                await contextFactory.CreateAsync(context, cancellationToken),
                cardId,
                request,
                cancellationToken);
            return TypedResults.Accepted($"/api/v1/operations/{operation.Id}", operation);
        }).AddEndpointFilter<IdempotencyKeyFilter>().RequireRateLimiting("sensitive");
    }

    private static ProblemHttpResult OidcUnavailable() =>
        TypedResults.Problem(
            statusCode: StatusCodes.Status503ServiceUnavailable,
            title: "Web sign-in is not configured",
            type: "https://azzu.tech/problems/oidc-not-configured",
            extensions: new Dictionary<string, object?>
            {
                ["code"] = "OIDC_NOT_CONFIGURED"
            });
}
