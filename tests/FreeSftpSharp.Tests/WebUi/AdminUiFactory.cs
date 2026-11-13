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
        builder.UseSetting("AdminAuth:UserName", ConfigureAdminCredential ? AdminUserName : "");
        builder.UseSetting("AdminAuth:PasswordHash", ConfigureAdminCredential ? AdminPasswordHash : "");
        // The login tests fail on purpose; the lockout itself is covered by LoginThrottleTests.
        builder.UseSetting("AdminAuth:MaxFailedLogins", "1000");

        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<ISettingsRepository>();
            services.AddSingleton<ISettingsRepository>(new InMemorySettingsRepository(new ServerSettings()));

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
