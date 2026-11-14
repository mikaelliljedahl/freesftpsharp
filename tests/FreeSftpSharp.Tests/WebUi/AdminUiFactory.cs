using SshServer.Interfaces.Security;
using FreeSftpSharp.Tests.Infrastructure;
using FxSsh.SshServerModule;
using FxSshSftpServer.Security;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SshServer.Interfaces;

namespace FreeSftpSharp.Tests.WebUi;

/// <summary>
/// Hosts the FxSshSftpServer admin UI in memory (TestServer). The SSH <see cref="HostedServer"/> is removed, and
/// the LiteDB settings repository is replaced by <see cref="InMemorySettingsRepository"/>, so no port is opened
/// and no config.db is created.
/// </summary>
public class AdminUiFactory : WebApplicationFactory<Program>
{
    public const string AdminUserName = "admin";
    public const string AdminPassword = "Correct-Horse-42";

    // The minimum iteration count keeps the login tests fast.
    private static readonly string AdminPasswordHash =
        PasswordHasher.Hash(AdminPassword, PasswordHasher.MinimumIterations);

    protected virtual bool ConfigureAdminCredential => true;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Production");
        // Framework files such as _framework/blazor.web.js are in wwwroot only after a publish; the build has a manifest for them.
        builder.UseStaticWebAssets();
        builder.UseSetting("AdminAuth:UserName", ConfigureAdminCredential ? AdminUserName : "");
        builder.UseSetting("AdminAuth:PasswordHash", ConfigureAdminCredential ? AdminPasswordHash : "");
        // The login tests fail on purpose; the lockout itself is covered by LoginThrottleTests.
        builder.UseSetting("AdminAuth:MaxFailedLogins", "1000");

        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<ISettingsRepository>();
            services.AddSingleton<ISettingsRepository>(new InMemorySettingsRepository(new ServerSettings()));
            // The SQL audit log would use the default database next to the app; the repository above does not create it.
            services.RemoveAll<SshServer.Interfaces.Audit.IAuditLog>();
            services.AddSingleton<SshServer.Interfaces.Audit.IAuditLog>(new InMemoryAuditLog());
            // The same for the webhooks: no store, so the webhook dispatcher does nothing.
            services.RemoveAll<SshServer.Interfaces.Webhooks.IWebhookStore>();
            services.AddSingleton<SshServer.Interfaces.Webhooks.IWebhookStore>(new SshServer.Settings.Sql.Webhooks.DisabledWebhookStore());

            var sshServer = services.Where(d => d.ServiceType == typeof(IHostedService) && d.ImplementationType == typeof(HostedServer)).ToList();
            foreach (var descriptor in sshServer)
                services.Remove(descriptor);
        });
    }

    public HttpClient CreateBrowser() =>
        CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });
}

public sealed class UnconfiguredAdminUiFactory : AdminUiFactory
{
    protected override bool ConfigureAdminCredential => false;
}

/// <summary>The admin UI with <c>SshServer:Port</c> and <c>SshServer:BindToAddress</c> in the configuration.</summary>
public sealed class ConfiguredListenAdminUiFactory : AdminUiFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting("SshServer:Port", "2200");
        builder.UseSetting("SshServer:BindToAddress", "127.0.0.1");
    }
}
