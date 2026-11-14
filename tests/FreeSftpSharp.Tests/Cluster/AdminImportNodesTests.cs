using System.Net;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings.Providers;
using FreeSftpSharp.Tests.WebUi;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Settings.Sql;
using SshServer.Settings.Sql.Admins;

namespace FreeSftpSharp.Tests.Cluster;

/// <summary>
/// Two admin hosts (FxSshSftpServer) with the same <c>AdminAuth</c> start at the same time on one empty settings database
/// (#149): the configured administrator is imported once, and both hosts start and open the admin UI.
/// </summary>
public sealed class AdminImportNodesTests
{
    private sealed class Node(TestDatabase database) : AdminUiFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<ISettingsRepository>();
                services.AddSingleton<ISettingsRepository>(_ => new SqlSettingsRepository(database.Options, createHostKey: () => TestCredentials.HostKey));
                services.RemoveAll<IAdminStore>();
                services.AddSingleton<IAdminStore>(new SqlAdminStore(database.Options));
            });
        }
    }

    [Theory]
    [MemberData(nameof(TestDatabase.Providers), MemberType = typeof(TestDatabase))]
    public async Task Two_nodes_that_start_at_the_same_time_import_the_configured_admin_once(string provider)
    {
        await using var database = await TestDatabase.CreateAsync(provider);
        await using var a = new Node(database);
        await using var b = new Node(database);

        var clients = await Task.WhenAll(Task.Run(a.CreateClient), Task.Run(b.CreateClient));

        await using (var db = new SettingsDbContext(database.Options))
            Assert.Equal([AdminUiFactory.AdminUserName], await db.Admins.Select(x => x.Username).ToListAsync(TestContext.Current.CancellationToken));
        foreach (var client in clients)
        {
            using (client)
            {
                var response = await client.GetAsync("/Login", TestContext.Current.CancellationToken);
                Assert.Equal(HttpStatusCode.OK, response.StatusCode); // 503 when the node found no administrator
            }
        }
    }
}
