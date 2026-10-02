using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.AspNetCore.DataProtection;
using Azzu.WebBff.Application;

namespace Azzu.WebBff.Api.Security;

// Explicit single-process DEV store. Production readiness remains fail-closed.
public sealed class DevelopmentTicketStore : ITicketStore, IServerSideTokenSessionStore, IDisposable
{
    private readonly MemoryCache _cache = new(new MemoryCacheOptions { SizeLimit = 10_000 });
    private readonly IDataProtector _protector;
    private readonly SemaphoreSlim[] _locks = Enumerable.Range(0, 64).Select(_ => new SemaphoreSlim(1, 1)).ToArray();

    public DevelopmentTicketStore(IDataProtectionProvider provider) =>
        _protector = provider.CreateProtector("Azzu.ServerSideTicket.v1");

    // Used by isolated unit tests. Runtime DI always supplies its configured provider.
    public DevelopmentTicketStore() : this(new EphemeralDataProtectionProvider()) { }

    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var key = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        Write(key, ticket);
        await Task.CompletedTask;
        return key;
    }

    public async Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        var gate = Gate(key);
        await gate.WaitAsync();
        try { if (Read(key) is not null) Write(key, ticket); }
        finally { gate.Release(); }
    }

    private void Write(string key, AuthenticationTicket ticket)
    {
        var expiry = ticket.Properties.ExpiresUtc;
        if (expiry is null || expiry <= DateTimeOffset.UtcNow)
        {
            _cache.Remove(key);
            return;
        }

        _cache.Set(key, _protector.Protect(TicketSerializer.Default.Serialize(ticket)), new MemoryCacheEntryOptions
        {
            AbsoluteExpiration = expiry,
            Size = 1
        });
    }

    private AuthenticationTicket? Read(string key)
    {
        if (!_cache.TryGetValue<byte[]>(key, out var value) || value is null) return null;
        var ticket = TicketSerializer.Default.Deserialize(_protector.Unprotect(value));
        if (ticket is null || ticket.Properties.ExpiresUtc is null || ticket.Properties.ExpiresUtc <= DateTimeOffset.UtcNow)
        { _cache.Remove(key); return null; }
        ticket.Properties.Items[IServerSideTokenSessionStore.SessionKey] = key;
        return ticket;
    }

    public Task<AuthenticationTicket?> RetrieveAsync(string key) => Task.FromResult(Read(key));

    public async Task RemoveAsync(string key)
    {
        var gate = Gate(key);
        await gate.WaitAsync();
        try { _cache.Remove(key); }
        finally { gate.Release(); }
    }

    public async Task<string> UseAsync(string key, Func<AuthenticationTicket, CancellationToken, Task<string>> operation,
        CancellationToken cancellationToken)
    {
        var gate = Gate(key);
        await gate.WaitAsync(cancellationToken);
        try
        {
            var ticket = Read(key) ?? throw new InvalidSessionContextException("The web session is missing or expired.");
            string result;
            try { result = await operation(ticket, cancellationToken); }
            catch (InvalidSessionContextException) { _cache.Remove(key); throw; }
            if (ticket.Properties.ExpiresUtc <= DateTimeOffset.UtcNow)
                throw new InvalidSessionContextException("The web session expired during token acquisition.");
            Write(key, ticket); // Retains the original session expiry; never extends it during refresh.
            return result;
        }
        finally { gate.Release(); }
    }

    private SemaphoreSlim Gate(string key) => _locks[(uint)StringComparer.Ordinal.GetHashCode(key) % (uint)_locks.Length];

    public void Dispose() => _cache.Dispose();
}
