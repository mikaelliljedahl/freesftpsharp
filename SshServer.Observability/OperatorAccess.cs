using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace SshServer.Observability;

/// <summary>Who may read the metrics and the health detail: a bearer key or an allowed network; else loopback only.</summary>
internal sealed class OperatorAccess
{
    private readonly byte[]? _key;
    private readonly IPNetwork[] _networks;
    private readonly bool _restricted;

    public OperatorAccess(PrometheusOptions options)
    {
        _key = string.IsNullOrEmpty(options.ApiKey) ? null : SHA256.HashData(Encoding.UTF8.GetBytes(options.ApiKey));
        var networks = new List<IPNetwork>();
        foreach (var entry in options.AllowedNetworks.Where(e => !string.IsNullOrWhiteSpace(e)))
        {
            var text = entry.Trim();
            networks.Add(IPNetwork.TryParse(text, out var network)
                ? network
                : IPAddress.TryParse(text, out var address)
                    ? new IPNetwork(address, address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128)
                    : throw new InvalidOperationException($"Observability: '{text}' is not an IP address or a CIDR network."));
        }
        _networks = networks.ToArray();
        _restricted = _key != null || _networks.Length > 0;
    }

    public bool IsAllowed(HttpContext context)
    {
        var remote = context.Connection.RemoteIpAddress;
        if (remote != null)
        {
            if (remote.IsIPv4MappedToIPv6)
                remote = remote.MapToIPv4();
            if (_networks.Any(n => n.Contains(remote)))
                return true;
            if (!_restricted && IPAddress.IsLoopback(remote))
                return true;
        }

        if (_key != null)
        {
            var header = context.Request.Headers.Authorization.ToString();
            const string prefix = "Bearer ";
            if (header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                var given = SHA256.HashData(Encoding.UTF8.GetBytes(header[prefix.Length..].Trim()));
                return CryptographicOperations.FixedTimeEquals(given, _key);
            }
        }
        return false;
    }
}
