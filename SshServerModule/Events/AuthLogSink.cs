#nullable enable
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SshServer.Interfaces.Events;

namespace SshServerModule.Events
{
    /// <summary>
    /// Writes every <see cref="AuthEvent"/> as one structured log line with a fixed text, for log readers such as
    /// fail2ban, for example <c>Auth LoginFailed user bob from 203.0.113.9 method password protocol SSH: wrong password</c>.
    /// The audit table gets the same events; this does not replace it.
    /// </summary>
    public sealed class AuthLogSink : IEventSink
    {
        private readonly ILogger _logger;

        public AuthLogSink(ILogger<AuthLogSink> logger)
        {
            _logger = logger;
        }

        public ValueTask HandleAsync(IEvent @event, CancellationToken ct)
        {
            if (@event is AuthEvent auth)
            {
                var level = auth.Type is AuthEventType.LoginFailed or AuthEventType.IpBanned ? LogLevel.Warning : LogLevel.Information;
                _logger.Log(level, "Auth {AuthEvent} user {Username} from {RemoteIp} method {Method} protocol {Protocol}: {Reason}",
                    auth.TypeName, auth.Username ?? "-", auth.RemoteIp ?? "-", auth.Method ?? "-", auth.Protocol, auth.Reason ?? "-");
            }
            return ValueTask.CompletedTask;
        }
    }
}
