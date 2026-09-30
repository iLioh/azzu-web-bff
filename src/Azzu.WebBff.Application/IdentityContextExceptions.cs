namespace Azzu.WebBff.Application;

public sealed class InvalidSessionContextException(string detail) : Exception(detail)
{
}

public sealed class CustomerIdentityNotLinkedException(string detail) : Exception(detail)
{
}

public sealed class CustomerIdentityMappingUnavailableException(string detail, Exception? innerException = null)
    : Exception(detail, innerException)
{
}

public sealed class AuthenticationContextUnavailableException(string detail) : Exception(detail)
{
}
