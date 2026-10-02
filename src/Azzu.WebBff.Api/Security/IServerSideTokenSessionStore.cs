using Microsoft.AspNetCore.Authentication;

namespace Azzu.WebBff.Api.Security;

// The lock/update must be atomic across replicas when a distributed implementation is introduced.
public interface IServerSideTokenSessionStore
{
    const string SessionKey = ".azzu.server-session";
    Task<string> UseAsync(string key, Func<AuthenticationTicket, CancellationToken, Task<string>> operation,
        CancellationToken cancellationToken);
}
