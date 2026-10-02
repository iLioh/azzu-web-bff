using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
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
    public const string BoundIdentityItem = "azzu.step-up-identity";

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
        if (properties?.Items.TryGetValue(BoundIdentityItem, out var expectedIdentity) == true)
        {
            try
            {
                if (principal is null || !string.Equals(expectedIdentity, IdentityFingerprint(principal), StringComparison.Ordinal)) return false;
            }
            catch (InvalidSessionContextException) { return false; }
        }

        if (properties is null
            || !properties.Items.TryGetValue(RequiredAuthenticationContextItem, out var requiredContext)
            || string.IsNullOrWhiteSpace(requiredContext))
        {
            return true;
        }

        return principal?.FindAll("acrs")
            .Any(claim => string.Equals(claim.Value, requiredContext, StringComparison.Ordinal)) == true;
    }

    public static void BindIdentity(AuthenticationProperties properties, ClaimsPrincipal principal) =>
        properties.Items[BoundIdentityItem] = IdentityFingerprint(principal);

    private static string IdentityFingerprint(ClaimsPrincipal principal)
    {
        var issuer = principal.FindFirstValue("iss");
        var subject = principal.FindFirstValue("sub");
        var objectId = principal.FindFirstValue("oid");
        var tenantId = principal.FindFirstValue("tid");
        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(subject)
            || !Guid.TryParse(objectId, out var oid) || oid == Guid.Empty
            || !Guid.TryParse(tenantId, out var tid) || tid == Guid.Empty)
        {
            throw new InvalidSessionContextException("Step-up requires a valid existing customer identity.");
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{issuer}\n{tid:D}\n{oid:D}")));
    }
}
