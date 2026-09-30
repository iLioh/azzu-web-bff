namespace Azzu.WebBff.Application;

public sealed class StepUpRequiredException(string operation, string detail) : Exception(detail)
{
    public string Operation { get; } = operation;
}
