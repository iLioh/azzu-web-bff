using System.ComponentModel.DataAnnotations;

namespace Azzu.WebBff.Api.Security;

public sealed class RequestValidationFilter : IEndpointFilter
{
    public ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var validationResults = new List<ValidationResult>();

        foreach (var argument in context.Arguments)
        {
            if (argument is null || argument is HttpContext || argument is CancellationToken)
            {
                continue;
            }

            var validationContext = new ValidationContext(argument);
            if (!Validator.TryValidateObject(argument, validationContext, validationResults, validateAllProperties: true))
            {
                var errors = validationResults
                    .GroupBy(result => result.MemberNames.FirstOrDefault() ?? string.Empty)
                    .ToDictionary(
                        group => group.Key,
                        group => group.Select(result => result.ErrorMessage ?? "Invalid value.").ToArray());

                return ValueTask.FromResult<object?>(Results.ValidationProblem(
                    errors,
                    statusCode: StatusCodes.Status400BadRequest,
                    title: "Request validation failed",
                    type: "https://azzu.tech/problems/request-validation-failed",
                    extensions: new Dictionary<string, object?>
                    {
                        ["code"] = "REQUEST_VALIDATION_FAILED",
                        [CorrelationIdMiddleware.HeaderName] = CorrelationIdMiddleware.GetCorrelationId(context.HttpContext)
                    }));
            }
        }

        return next(context);
    }
}

