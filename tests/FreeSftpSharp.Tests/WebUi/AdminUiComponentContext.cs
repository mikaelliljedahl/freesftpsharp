using System.Net;
using System.Security.Claims;
using Bunit;
using Bunit.TestDoubles;
using FreeSftpSharp.Tests.Infrastructure;
using FxSsh.SshServerModule;
using FxSsh.SshServerModule.Security;
using FxSshSftpServer.Components.Shared;
using FxSshSftpServer.Security;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Connections;
using SshServer.Interfaces.Security;
using SshServer.Interfaces.Users;
using SshServerModule.Connections;

namespace FreeSftpSharp.Tests.WebUi;

/// <summary>
/// A bUnit context for the admin UI pages: an in-memory settings repository, the real ban tracker with a fake clock,
/// the toast service and the listen options. JavaScript calls are accepted and do nothing (loose mode). The page runs as
/// a signed-in super admin; <see cref="SignInAs"/> changes the administrator.
/// </summary>
public class AdminUiComponentContext : BunitContext
{
    public InMemorySettingsRepository Repository { get; }
    public FakeTimeProvider Clock { get; } = new(new DateTimeOffset(2026, 11, 1, 12, 0, 0, TimeSpan.Zero));
    public LoginBanTracker Bans { get; }
    public InMemoryAuditLog AuditLog { get; } = new();
    public SshServerOptions ListenOptions { get; } = new();
    public ConnectionRegistry Registry { get; }
    public InMemoryAdminStore AdminStore { get; } = new();
    public AdminAdministrationService Administration { get; }

    private readonly BunitAuthorizationContext _authorization;

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
        Administration = new AdminAdministrationService(AdminStore, Repository, time: Clock, hashIterations: PasswordHasher.MinimumIterations);

        Services.AddSingleton<ISettingsRepository>(Repository);
        Services.AddSingleton<IIpBanService>(Bans);
        Services.AddSingleton<IConnectionRegistry>(Registry);
        Services.AddSingleton<TimeProvider>(Clock);
        Services.AddSingleton(Microsoft.Extensions.Options.Options.Create(ListenOptions));
        Services.AddScoped<ToastService>();
        Services.AddSingleton<SshServer.Interfaces.Audit.IAuditLog>(AuditLog);
        Services.AddSingleton<IAdminStore>(AdminStore);
        Services.AddSingleton(Administration);
        // The same scoped services as the web host (AdminAuthenticationSetup.AddAdminAuthentication).
        Services.AddScoped<CurrentAdmin>();
        Services.AddScoped<AdminScopedSettingsRepository>();
        Services.AddScoped<ScopedAuditLog>();
        Services.AddScoped<ScopedConnections>();
        Services.AddScoped(sp => new UserAdministrationService(sp.GetRequiredService<AdminScopedSettingsRepository>()));
        JSInterop.Mode = JSRuntimeMode.Loose;

        _authorization = AddAuthorization();
        SignInAs(AdminPermissions.SuperAdmin);
    }

    public ToastService Toasts => Services.GetRequiredService<ToastService>();

    /// <summary>The signed-in administrator of the rendered pages (its claims, as the login cookie has them).</summary>
    public void SignInAs(AdminPermissions permissions, int? scopeRoleId = null, string name = "admin")
    {
        var principal = AdminClaims.CreatePrincipal(new Admin { Username = name, Permissions = permissions, ScopeRoleId = scopeRoleId });
        _authorization.SetAuthorized(name);
        _authorization.SetClaims(principal.Claims.Where(c => c.Type != ClaimTypes.Name).ToArray());
    }

    /// <summary>Bans an address with one failed login.</summary>
    public void Ban(string address) =>
        Bans.RecordFailure(IPAddress.Parse(address), new BanPolicy(1, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(30), false));
}
