using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace FxSsh.SshServerModule.Security
{
    /// <summary>The local addresses the server listens on, from <c>ServerSettings.BindToAddress</c>.</summary>
    internal static class ListenAddresses
    {
        /// <summary>
        /// Empty or null: <see cref="IPAddress.IPv6Any"/> (FxSsh then listens dual stack, IPv4 and IPv6, as before).
        /// "::" also listens on everything, so other entries are then not needed and are dropped (a second socket on
        /// the same port would fail). Invalid entries are logged and skipped; when no entry is valid the server does
        /// not start, so that it never listens on more addresses than the administrator asked for.
        /// </summary>
        internal static IReadOnlyList<IPAddress> Resolve(IEnumerable<string> bindToAddress, ILogger logger)
        {
            var entries = (bindToAddress ?? Enumerable.Empty<string>()).Where(e => !string.IsNullOrWhiteSpace(e)).ToList();
            if (entries.Count == 0)
                return new[] { IPAddress.IPv6Any };

            var addresses = new List<IPAddress>();
            foreach (var entry in entries)
            {
                var text = entry.Trim();
                if (text == "*")
                    text = "::";
                if (!IPAddress.TryParse(text, out var address) || text.Contains('%'))
                {
                    logger.LogError("Ignoring the invalid entry \"{Entry}\" in BindToAddress: it is not an IP address.", entry);
                    continue;
                }
                if (address.IsIPv4MappedToIPv6)
                    address = address.MapToIPv4();
                if (!addresses.Contains(address))
                    addresses.Add(address);
            }

            if (addresses.Count == 0)
                throw new InvalidOperationException(
                    "BindToAddress has no valid IP address. Fix the setting, or make it empty to listen on all addresses.");

            if (addresses.Contains(IPAddress.IPv6Any) && addresses.Count > 1)
            {
                logger.LogInformation("BindToAddress contains \"::\" (all addresses, IPv4 and IPv6); the other entries are not needed.");
                return new[] { IPAddress.IPv6Any };
            }

            return addresses;
        }
    }
}
