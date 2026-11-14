#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using SshServer.Interfaces.Net;

namespace SshServerModule.Proxy
{
    /// <summary>
    /// The PROXY protocol on the SSH listener (issue #75), the <c>Proxy</c> section. Off by default. With
    /// <c>Proxy:AllowedSources</c> (the addresses or CIDR networks of the load balancers, for example HAProxy with
    /// <c>send-proxy-v2</c>) every connection must come from an allowed source and start with a PROXY header (version 1
    /// or 2); the server then uses the client address of the header for the IP rules, the bans, the connections and the
    /// audit log. A connection from another source, without a header or with a header that is not valid is closed before
    /// the SSH handshake. <c>Proxy:HeaderTimeoutSeconds</c> (default 5) is the time for the header.
    /// </summary>
    public sealed class ProxyProtocolOptions
    {
        public const string SectionName = "Proxy";

        public IReadOnlyList<IPNetwork> AllowedSources { get; init; } = [];

        public TimeSpan HeaderTimeout { get; init; } = TimeSpan.FromSeconds(5);

        /// <summary>True when at least one source is allowed.</summary>
        public bool Enabled => AllowedSources.Count > 0;

        /// <summary>The options for these sources; an entry that is not an address or a network is an error.</summary>
        public static ProxyProtocolOptions Create(IEnumerable<string> allowedSources, TimeSpan? headerTimeout = null)
        {
            var entries = allowedSources.Where(e => !string.IsNullOrWhiteSpace(e)).Select(e => e.Trim()).ToList();
            var invalid = CidrNotation.FindInvalid(entries);
            if (invalid.Count > 0)
                throw new InvalidOperationException($"Proxy:AllowedSources has an entry that is not an IP address or a CIDR network: {string.Join(", ", invalid)}.");
            return new ProxyProtocolOptions
            {
                AllowedSources = CidrNotation.ParseValid(entries),
                HeaderTimeout = headerTimeout ?? TimeSpan.FromSeconds(5),
            };
        }

        /// <summary>Reads the section. <c>AllowedSources</c> is a comma separated string or an array.</summary>
        public static ProxyProtocolOptions FromConfiguration(IConfiguration configuration)
        {
            var section = configuration.GetSection(SectionName);
            var sources = section.GetSection("AllowedSources");
            var raw = sources.Value != null
                ? new[] { sources.Value }
                : sources.GetChildren().Select(c => c.Value).Where(v => v != null).Cast<string>().ToArray();
            var timeoutText = section["HeaderTimeoutSeconds"];
            var seconds = 5;
            if (!string.IsNullOrWhiteSpace(timeoutText)
                && (!int.TryParse(timeoutText.Trim(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out seconds)
                    || seconds is < 1 or > 60))
                throw new InvalidOperationException("Proxy:HeaderTimeoutSeconds must be between 1 and 60.");
            return Create(raw.SelectMany(v => v.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)),
                TimeSpan.FromSeconds(seconds));
        }

        /// <summary>True when <paramref name="remote"/> is the address of an allowed load balancer.</summary>
        public bool IsAllowedSource(EndPoint? remote) =>
            remote is IPEndPoint ip && CidrNotation.Contains(AllowedSources, CidrNotation.Normalize(ip.Address));

        /// <summary>
        /// The step before the SSH session (<c>FxSsh.SshServer.ConnectionPreface</c>): refuses a source that is not allowed,
        /// reads the header and returns the client address of the header (null: the address of the connection).
        /// </summary>
        public async Task<EndPoint?> AcceptAsync(Socket socket, CancellationToken ct)
        {
            if (!IsAllowedSource(socket.RemoteEndPoint))
                throw new ProxyProtocolException($"{socket.RemoteEndPoint} is not an allowed source of the PROXY protocol (Proxy:AllowedSources).");

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(HeaderTimeout);
            await using var stream = new NetworkStream(socket, ownsSocket: false);
            try
            {
                var header = await ProxyProtocolReader.ReadAsync(stream, timeout.Token);
                return header.Source;
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                throw new ProxyProtocolException($"No PROXY protocol header within {HeaderTimeout.TotalSeconds} s.");
            }
        }
    }
}
