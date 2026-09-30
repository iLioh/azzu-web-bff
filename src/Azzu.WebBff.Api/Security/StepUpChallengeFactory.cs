using System.Security.Claims;
using System.Text.Json;
using Azzu.WebBff.Api.Configuration;
using Azzu.WebBff.Application;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Azzu.WebBff.Api.Security;

public sealed class StepUpChallengeFactory(IOptions<StepUpOptions> options)
{
    public const string ClaimsParameter = "claims";
    public const string RequiredAuthenticationContextItem = "azzu.required-authentication-context";
    public const string DefaultOperation = "sensitive-operation";

    public AuthenticationProperties Create(string operation, string redirectUri)
    {
        if (!options.Value.AuthenticationContexts.TryGetValue(operation, out var authenticationContextId)
            || string.IsNullOrWhiteSpace(authenticationContextId))
        {
            throw new AuthenticationContextUnavailableException(
                $"No Conditional Access authentication context is configured for operation '{operation}'.");
        }

        var claimsRequest = JsonSerializer.Serialize(new
        {
            id_token = new
            {
                acrs = new
                {
                    essential = true,
                    value = authenticationContextId
                }
            }
        });

        var properties = new AuthenticationProperties { RedirectUri = redirectUri };
        properties.Parameters[ClaimsParameter] = claimsRequest;
        properties.Items[RequiredAuthenticationContextItem] = authenticationContextId;
        return properties;
    }

    public static bool HasRequiredContext(AuthenticationProperties? properties, ClaimsPrincipal? principal)
    {
        if (properties is null
            || !properties.Items.TryGetValue(RequiredAuthenticationContextItem, out var requiredContext)
            || string.IsNullOrWhiteSpace(requiredContext))
        {
            return true;
        }

        return principal?.FindAll("acrs")
            .Any(claim => string.Equals(claim.Value, requiredContext, StringComparison.Ordinal)) == true;
    }
}
