namespace Azzu.WebBff.Application;

public sealed class BankingDependencyUnavailableException(string detail) : Exception(detail)
{
}

