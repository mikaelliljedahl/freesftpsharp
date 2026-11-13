using System.Reflection;
using FreeSftpSharp.Tests.Infrastructure;
using FxSsh.SshServerModule;
using FxSsh.SshServerModule.Security;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SshServer.Filesystem.LocalDisk;
using SshServer.Interfaces;
using SshServerModule.Storage;

namespace FreeSftpSharp.Tests.Unit;

/// <summary><c>AddSshServerSecurity</c>: the server and the admin UI share one ban state.</summary>
public sealed class SecurityRegistrationTests
{
    [Fact]
    public void HostedServer_and_IIpBanService_use_the_same_ban_tracker()
    {
        var repository = new InMemorySettingsRepository(new ServerSettings());
        var services = new ServiceCollection()
            .AddLogging()
            .AddSingleton<ISettingsRepository>(repository)
            .AddSshServerStorage()
            .AddLocalDiskStorage()
            .AddSingleton<HostedServer>()
            .AddSshServerSecurity();

        using var provider = services.BuildServiceProvider();
        var tracker = provider.GetRequiredService<LoginBanTracker>();
        var server = provider.GetRequiredService<HostedServer>();

        Assert.Same(tracker, provider.GetRequiredService<IIpBanService>());
        Assert.Same(TimeProvider.System, tracker.Time);
        var used = typeof(HostedServer).GetField("_bans", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(server);
        Assert.Same(tracker, used);
    }
}
