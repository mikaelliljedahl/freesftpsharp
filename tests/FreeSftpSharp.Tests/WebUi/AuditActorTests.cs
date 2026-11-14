using Bunit;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings;
using FxSshSftpServer.Components.Pages;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Audit;
using SshServer.Interfaces.Events;
using SshServer.Interfaces.Groups;
using SshServer.Interfaces.Storage;
using SshServer.Interfaces.Users;
using SshServer.Settings.Sql;
using SshServerModule.Storage;
using AuditPage = FxSshSftpServer.Components.Pages.Audit;

namespace FreeSftpSharp.Tests.WebUi;

/// <summary>
/// The changes of users, groups, virtual folders and server settings in the admin UI have the signed-in administrator
/// as their actor in the audit log (#134), over the real SQLite settings repository.
/// </summary>
public sealed class AuditActorTests : AdminUiComponentContext
{
    private readonly SqliteConnection _connection = new("Data Source=:memory:");
    private readonly TempDirectory _root = new();
    private readonly SqlSettingsRepository _sql;

    public AuditActorTests()
    {
        _connection.Open();
        var options = new DbContextOptionsBuilder<SettingsDbContext>().UseSqlite(_connection).Options;
        var actors = new AuditActorContext();
        _sql = new SqlSettingsRepository(options, createHostKey: () => TestCredentials.HostKey, events: Events, actors: actors);
        Services.AddSingleton(actors);
        Services.AddSingleton<ISettingsRepository>(_sql);
        SignInAs(AdminPermissions.SuperAdmin, name: "alice-admin");
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _connection.Dispose();
            _root.Dispose();
        }
        base.Dispose(disposing);
    }

    private List<ProviderEvent> Changes(ProviderObjectType type) =>
        Events.Published.OfType<ProviderEvent>().Where(e => e.ObjectType == type).ToList();

    [Fact]
    public void A_settings_change_on_the_page_has_the_administrator_as_actor()
    {
        var page = Render<ServerSettingsPage>();

        page.Find("#server-banner").Change("Audited");
        page.Find("#server-settings-form").Submit();

        var change = Assert.Single(Changes(ProviderObjectType.ServerSettings));
        Assert.Equal("alice-admin", change.Actor);
    }

    [Fact]
    public void User_group_and_folder_changes_have_the_administrator_as_actor()
    {
        var users = Services.GetRequiredService<UserAdministrationService>();
        var groups = Services.GetRequiredService<GroupService>();
        var folders = Services.GetRequiredService<VirtualFolderService>();

        Assert.True(users.TryAdd(new User { Username = "bob", UserRootDirectory = _root.Path, WhitelistedIps = [] }));
        var group = new Group { Name = "staff" };
        Assert.True(groups.TryAdd(group));
        var folder = new VirtualFolder { Name = "shared", Storage = new StorageConfig { Provider = "local", Options = "{}" } };
        Assert.True(folders.TryAdd(folder));
        Assert.True(folders.Remove(folder.Id));
        Assert.True(groups.Remove(group.Id));
        Assert.True(users.Remove("bob"));

        var changes = Events.Published.OfType<ProviderEvent>().ToList();
        Assert.Equal(6, changes.Count);
        Assert.All(changes, e => Assert.Equal("alice-admin", e.Actor));
    }

    [Fact]
    public void A_change_outside_the_admin_services_is_made_by_the_system()
    {
        Assert.True(_sql.AddUser(new User { Username = "jit", UserRootDirectory = _root.Path, WhitelistedIps = [] }));

        Assert.Equal(AuditActorContext.System, Assert.Single(Changes(ProviderObjectType.User)).Actor);
    }

    [Fact]
    public async Task The_audit_page_shows_the_actor_in_its_own_column()
    {
        await AuditLog.AppendAsync(new AuditEntry
        {
            TimestampUtc = DateTime.UtcNow, Category = "Provider", Type = "Update", Status = "Ok", Path = "User/bob", Actor = "alice-admin",
        }, Xunit.TestContext.Current.CancellationToken);

        var page = Render<AuditPage>();

        page.WaitForAssertion(() => Assert.Equal("1", page.Find("#audit-count").TextContent));
        Assert.Contains("By", page.Find("#audit-table thead").TextContent);
        Assert.Equal("alice-admin", page.Find("#audit-table tbody tr .audit-actor").TextContent.Trim());
    }
}
