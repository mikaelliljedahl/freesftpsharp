using System.Net;
using Bunit;
using FreeSftpSharp.Tests.Infrastructure;
using FxSsh.SshServerModule;
using FxSsh.SshServerModule.Security;
using FxSshSftpServer.Components.Shared;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using SshServer.Interfaces;
using SshServer.Interfaces.Connections;
using SshServerModule.Connections;

namespace FreeSftpSharp.Tests.WebUi;

/// <summary>
/// A bUnit context for the admin UI pages: an in-memory settings repository, the real ban tracker with a fake clock,
/// the toast service and the listen options. JavaScript calls are accepted and do nothing (loose mode).
/// </summary>
public class AdminUiComponentContext : BunitContext
{
    public InMemorySettingsRepository Repository { get; }
    public FakeTimeProvider Clock { get; } = new(new DateTimeOffset(2026, 11, 1, 12, 0, 0, TimeSpan.Zero));
    public LoginBanTracker Bans { get; }
    public SshServerOptions ListenOptions { get; } = new();
    public ConnectionRegistry Registry { get; }

    public AdminUiComponentContext()
    {
        Repository = new InMemorySettingsRepository(new ServerSettings
        {
            ServerRsaKey = TestCredentials.HostKey,
            ListenToPort = 2222,
            BindToAddress = new List<string>(),
            BlacklistedIps = new List<string>(),
            WhitelistedIps = new List<string>(),
        });
        Bans = new LoginBanTracker(Clock);
        Registry = new ConnectionRegistry(Clock);

        Services.AddSingleton<ISettingsRepository>(Repository);
        Services.AddSingleton<SshServer.Interfaces.Users.UserAdministrationService>();
        Services.AddSingleton<IIpBanService>(Bans);
        Services.AddSingleton<IConnectionRegistry>(Registry);
        Services.AddSingleton<TimeProvider>(Clock);
        Services.AddSingleton(Microsoft.Extensions.Options.Options.Create(ListenOptions));
        Services.AddScoped<ToastService>();
        JSInterop.Mode = JSRuntimeMode.Loose;
    }

    public ToastService Toasts => Services.GetRequiredService<ToastService>();

    /// <summary>Bans an address with one failed login.</summary>
    public void Ban(string address) =>
        Bans.RecordFailure(IPAddress.Parse(address), new BanPolicy(1, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(30), false));
}
