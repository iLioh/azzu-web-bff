namespace Azzu.WebBff.Api.Security;

public interface IProductionSessionSecurityReadiness
{
    bool HasDistributedServerSideSessionStore { get; }
    bool HasSharedDataProtectionKeyStore { get; }
}

public sealed class UnconfiguredProductionSessionSecurityReadiness : IProductionSessionSecurityReadiness
{
    public bool HasDistributedServerSideSessionStore => false;

    public bool HasSharedDataProtectionKeyStore => false;
}

