using System.Net;
using Microsoft.AspNetCore.HttpOverrides;

namespace Azzu.WebBff.Api.Security;

public static class TrustedProxyConfiguration
{
    public static IServiceCollection AddAzzuTrustedProxy(this IServiceCollection services, IConfiguration configuration)
    {
        var section = configuration.GetSection("Gateway");
        if (!section.GetValue<bool>("ForwardedHeadersEnabled")) return services;

        var proxies = section.GetSection("TrustedProxyAddresses").Get<string[]>() ?? [];
        var hosts = section.GetSection("AllowedForwardedHosts").Get<string[]>() ?? [];
        var limit = section.GetValue("ForwardLimit", 1);
        if (proxies.Length == 0 || hosts.Length == 0 || limit is < 1 or > 3 ||
            proxies.Any(value => !IPAddress.TryParse(value, out var address) ||
                address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) ||
            hosts.Any(value => Uri.CheckHostName(value) != UriHostNameType.Dns || value.Contains('*')))
            throw new InvalidOperationException("Forwarded headers require explicit trusted proxy IPs, exact allowed hostnames and a bounded hop limit.");

        services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor |
                ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
            options.ForwardLimit = limit;
            options.KnownNetworks.Clear();
            options.KnownProxies.Clear();
            foreach (var proxy in proxies) options.KnownProxies.Add(IPAddress.Parse(proxy));
            foreach (var host in hosts) options.AllowedHosts.Add(host);
        });
        return services;
    }
}
