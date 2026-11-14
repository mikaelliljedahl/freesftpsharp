#nullable enable
using System.Threading;
using System.Threading.Tasks;
using SshServer.Interfaces.Cluster;
using SshServer.Interfaces.Events;

namespace SshServerModule.Cluster
{
    /// <summary>
    /// Raises the stored settings version for every provider event (a change of the settings by this node), so that the
    /// other nodes reload their caches (issue #75). A sink: the change never waits for it.
    /// </summary>
    public sealed class SettingsVersionSink : IEventSink
    {
        private readonly ISettingsVersionStore _versions;

        public SettingsVersionSink(ISettingsVersionStore versions)
        {
            _versions = versions;
        }

        public async ValueTask HandleAsync(IEvent @event, CancellationToken ct)
        {
            if (@event is ProviderEvent)
                await _versions.BumpAsync(ct);
        }
    }
}
