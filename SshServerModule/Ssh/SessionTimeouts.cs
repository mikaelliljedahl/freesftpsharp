using SshServer.Interfaces;
using System;

namespace FxSsh.SshServerModule
{
    /// <summary>
    /// Maps <see cref="ServerSettings.IdleTimeout"/> to the FxSsh session timers.
    /// FxSsh keepalive probes count as traffic for the inactivity timer, so the two are not used together:
    /// <list type="bullet">
    /// <item>IdleTimeout &gt; 0: the session is closed after that many seconds without traffic. This also
    /// removes dead clients.</item>
    /// <item>IdleTimeout &lt;= 0 ("no timeout"): no idle limit, but the server sends a keepalive probe every
    /// <see cref="HostedServer.KeepaliveInterval"/> and closes the session after three unanswered probes.</item>
    /// </list>
    /// </summary>
    internal readonly record struct SessionTimeouts(TimeSpan? InactivityTimeout, TimeSpan? KeepaliveInterval)
    {
        internal static SessionTimeouts FromSettings(ServerSettings settings)
        {
            if (settings.IdleTimeout > 0)
                return new SessionTimeouts(TimeSpan.FromSeconds(settings.IdleTimeout), null);

            return new SessionTimeouts(null, HostedServer.KeepaliveInterval);
        }
    }
}
