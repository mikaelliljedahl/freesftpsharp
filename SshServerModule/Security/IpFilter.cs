using Microsoft.Extensions.Logging;
using SshServer.Interfaces;
using SshServer.Interfaces.Net;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;

namespace FxSsh.SshServerModule.Security
{
    public enum IpFilterResult
    {
        Allowed,
        /// <summary>The address is in <see cref="ServerSettings.BlacklistedIps"/>.</summary>
        Blacklisted,
        /// <summary>Whitelist mode is on and the address is not in <see cref="ServerSettings.WhitelistedIps"/>.</summary>
        NotWhitelisted,
        /// <summary>The address is auto-banned.</summary>
        Banned,
        /// <summary>The remote end point is not an IP end point.</summary>
        Rejected,
    }

    /// <summary>
    /// Decides whether a new connection may continue, from the global blacklist, the global whitelist mode and the
    /// auto-bans. The settings are read for each connection, so changes in the admin UI apply at once. Invalid
    /// entries are skipped and logged once each.
    /// </summary>
    public sealed class IpFilter
    {
        private readonly ILogger _logger;
        private readonly ConcurrentDictionary<string, bool> _reportedInvalid = new(StringComparer.Ordinal);

        public IpFilter(ILogger logger)
        {
            _logger = logger;
        }

        public IpFilterResult Check(EndPoint remoteEndPoint, ServerSettings settings, IIpBanService bans)
        {
            if (remoteEndPoint is not IPEndPoint ip)
                return IpFilterResult.Rejected;
            var address = CidrNotation.Normalize(ip.Address);

            if (CidrNotation.Contains(Parse(settings.BlacklistedIps, nameof(ServerSettings.BlacklistedIps)), address))
                return IpFilterResult.Blacklisted;

            if (settings.OnlyWhitelistedIps && settings.WhitelistedIps is { Count: > 0 }
                && !CidrNotation.Contains(Parse(settings.WhitelistedIps, nameof(ServerSettings.WhitelistedIps)), address))
                return IpFilterResult.NotWhitelisted;

            if (bans != null && bans.IsBanned(address))
                return IpFilterResult.Banned;

            return IpFilterResult.Allowed;
        }

        private IReadOnlyList<IPNetwork> Parse(List<string> entries, string settingName) =>
            CidrNotation.ParseValid(entries, invalid =>
            {
                if (_reportedInvalid.TryAdd(settingName + "|" + invalid, true))
                    _logger.LogWarning("Ignoring the invalid entry \"{Entry}\" in {Setting}: it is not an IP address or a CIDR network.",
                        invalid, settingName);
            });
    }
}
