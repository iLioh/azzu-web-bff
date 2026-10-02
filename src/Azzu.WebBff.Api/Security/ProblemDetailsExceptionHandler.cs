using Azzu.WebBff.Application;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Azzu.WebBff.Api.Security;

public sealed class ProblemDetailsExceptionHandler(
    ILogger<ProblemDetailsExceptionHandler> logger,
    IProblemDetailsService problemDetailsService) : IExceptionHandler
{
    private static readonly Action<ILogger, string, Exception?> LogUnhandledRequest =
        LoggerMessage.Define<string>(
            LogLevel.Error,
            new EventId(1001, "WebBffRequestFailed"),
            "Web BFF request failed with {ProblemCode}.");

    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        var (status, title, type, code) = exception switch
        {
            BankingReauthenticationRequiredException => (
                StatusCodes.Status401Unauthorized,
                "Banking access requires reauthentication",
                "https://azzu.tech/problems/banking-reauthentication-required",
                "BANKING_REAUTHENTICATION_REQUIRED"),
            InvalidSessionContextException => (
                StatusCodes.Status401Unauthorized,
                "The web session is invalid",
                "https://azzu.tech/problems/invalid-session-context",
                "INVALID_SESSION_CONTEXT"),
            CustomerIdentityNotLinkedException => (
                StatusCodes.Status403Forbidden,
                "Banking customer context is not available",
                "https://azzu.tech/problems/customer-identity-not-linked",
                "CUSTOMER_IDENTITY_NOT_LINKED"),
            CustomerIdentityMappingUnavailableException => (
                StatusCodes.Status503ServiceUnavailable,
                "Customer identity mapping is temporarily unavailable",
                "https://azzu.tech/problems/customer-identity-mapping-unavailable",
                "CUSTOMER_IDENTITY_MAPPING_UNAVAILABLE"),
            CustomerAccessDeniedException => (
                StatusCodes.Status403Forbidden,
                "Banking access is not permitted",
                "https://azzu.tech/problems/customer-access-denied",
                "CUSTOMER_ACCESS_DENIED"),
            AuthenticationContextUnavailableException => (
                StatusCodes.Status503ServiceUnavailable,
                "Step-up authentication is not configured",
                "https://azzu.tech/problems/authentication-context-unavailable",
                "AUTHENTICATION_CONTEXT_UNAVAILABLE"),
            BankingDependencyUnavailableException => (
                StatusCodes.Status503ServiceUnavailable,
                "Banking service is temporarily unavailable",
                "https://azzu.tech/problems/banking-dependency-unavailable",
                "BANKING_DEPENDENCY_UNAVAILABLE"),
            StepUpRequiredException => (
                StatusCodes.Status401Unauthorized,
                "Additional authentication is required",
                "https://azzu.tech/problems/step-up-required",
                "STEP_UP_REQUIRED"),
            _ => (
                StatusCodes.Status500InternalServerError,
                "An unexpected error occurred",
                "https://azzu.tech/problems/internal-error",
                "INTERNAL_ERROR")
        };

        if (exception is InvalidSessionContextException)
        {
            await httpContext.SignOutAsync(AuthenticationExtensions.CookieScheme);
        }

        if (exception is StepUpRequiredException stepUp)
        {
            var operation = Uri.EscapeDataString(stepUp.Operation);
            httpContext.Response.Headers.Append(
                "WWW-Authenticate",
                $"OIDC error=\"insufficient_user_authentication\", step_up_uri=\"/api/v1/auth/step-up?operation={operation}\"");
        }
        if (exception is BankingReauthenticationRequiredException)
            httpContext.Response.Headers.Append("WWW-Authenticate",
                "OIDC error=\"interaction_required\", reauthentication_uri=\"/api/v1/auth/login\"");

        LogUnhandledRequest(logger, code, exception);

        var problem = new ProblemDetails
        {
            Status = status,
            Title = title,
            Type = type,
            Detail = status == StatusCodes.Status500InternalServerError
                ? "The request could not be completed."
                : exception.Message,
            Instance = httpContext.Request.Path
        };
        problem.Extensions["code"] = code;
        problem.Extensions[CorrelationIdMiddleware.HeaderName] = CorrelationIdMiddleware.GetCorrelationId(httpContext);

        httpContext.Response.StatusCode = status;
        httpContext.Response.ContentType = "application/problem+json";

        return await problemDetailsService.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = httpContext,
            ProblemDetails = problem,
            Exception = exception
        });
    }
}
