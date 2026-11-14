using Bunit;
using FreeSftpSharp.Tests.Settings;
using FxSshSftpServer.Components.Pages;
using FxSshSftpServer.Security;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Audit;
using SshServer.Interfaces.Connections;
using ConnectionsPage = FxSshSftpServer.Components.Pages.Connections;

namespace FreeSftpSharp.Tests.WebUi;

/// <summary>
/// The permissions and the scope are enforced by the services behind the pages (#60), not only by the page policies:
/// an administrator scoped to tenant-a sees and changes only the users of tenant-a.
/// </summary>
public sealed class AdminScopeTests : AdminUiComponentContext
{
    private static readonly TimeSpan SaveTimeout = TimeSpan.FromSeconds(15);

    private readonly TempDirectory _root = new();
    private readonly int _tenantA;
    private readonly int _tenantB;

    public AdminScopeTests()
    {
        _tenantA = AddRole("tenant-a");
        _tenantB = AddRole("tenant-b");
        AddUser("a-user", _tenantA);
        AddUser("a-other", _tenantA);
        AddUser("b-user", _tenantB);
        AddUser("no-role", null);
    }

    private int AddRole(string name)
    {
        var role = new Role { Name = name };
        Assert.True(AdminStore.AddRoleAsync(role, CancellationToken.None).GetAwaiter().GetResult());
        return role.Id;
    }

    private void AddUser(string name, int? roleId) =>
        Repository.AddUser(new User { Username = name, UserRootDirectory = _root.Path, RoleId = roleId, WhitelistedIps = new List<string>() });

    private AdminScopedSettingsRepository Scoped => Services.GetRequiredService<AdminScopedSettingsRepository>();

    private void SignInAsTenantA(AdminPermissions permissions = AdminPermissions.ManageUsers) =>
        SignInAs(permissions, _tenantA, "tenant-a-admin");

    [Fact]
    public void A_scoped_administrator_lists_only_the_users_of_its_role()
    {
        SignInAsTenantA();

        var page = Render<Users>();

        var table = page.Find("#user-table").TextContent;
        Assert.Contains("a-user", table);
        Assert.Contains("a-other", table);
        Assert.DoesNotContain("b-user", table);
        Assert.DoesNotContain("no-role", table);
    }

    [Fact]
    public void A_scoped_administrator_cannot_open_change_or_delete_a_user_of_another_role()
    {
        SignInAsTenantA();

        Assert.Null(Scoped.GetUser("b-user"));
        Assert.Null(Scoped.GetUser("no-role"));
        Assert.NotNull(Scoped.GetUser("a-user"));

        var other = Repository.GetUser("b-user");
        var copy = new User { Username = other.Username, UserRootDirectory = "/elsewhere", RoleId = _tenantA };
        Assert.False(Scoped.UpdateUser(copy));
        Assert.False(Scoped.RemoveUser("b-user"));
        Assert.Equal(_root.Path, Repository.GetUser("b-user").UserRootDirectory);
    }

    [Fact]
    public void A_scoped_administrator_cannot_move_its_user_to_another_role()
    {
        SignInAsTenantA();

        Assert.NotNull(Scoped.GetUser("a-user"));
        // A changed copy, as the page sends it (the in-memory repository would hand out the stored object).
        var user = new User { Username = "a-user", UserRootDirectory = "/changed", RoleId = _tenantB };
        Assert.True(Scoped.UpdateUser(user));

        var stored = Repository.GetUser("a-user");
        Assert.Equal(_tenantA, stored.RoleId);
        Assert.Equal("/changed", stored.UserRootDirectory);
    }

    [Fact]
    public void A_scoped_administrator_cannot_create_a_user_without_its_role()
    {
        SignInAsTenantA();

        var withoutRole = new User { Username = "new-a", UserRootDirectory = _root.Path };
        Assert.True(Scoped.AddUser(withoutRole));
        Assert.Equal(_tenantA, Repository.GetUser("new-a").RoleId);

        Assert.Throws<AdminAccessDeniedException>(() =>
            Scoped.AddUser(new User { Username = "new-b", UserRootDirectory = _root.Path, RoleId = _tenantB }));
        Assert.Null(Repository.GetUser("new-b"));
    }

    [Fact]
    public void A_user_created_on_the_page_by_a_scoped_administrator_gets_its_role()
    {
        SignInAsTenantA();
        var page = Render<Users>();

        page.Find("#add-user").Click();
        page.Find("#username").Change("carol");
        page.Find("#root-directory").Change(_root.Path);
        page.Find("#new-password").Change("long-enough-1");
        page.Find("#confirm-password").Change("long-enough-1");
        page.Find("#user-form").Submit();

        page.WaitForAssertion(() => Assert.NotNull(Repository.GetUser("carol")), SaveTimeout);
        Assert.Equal(_tenantA, Repository.GetUser("carol").RoleId);
    }

    [Fact]
    public void An_administrator_without_a_scope_sees_every_user_and_may_set_a_role()
    {
        SignInAs(AdminPermissions.ManageUsers);

        Assert.Equal(4, Scoped.GetAllUsers().Count);
        Assert.NotNull(Scoped.GetUser("no-role"));
        Assert.True(Scoped.UpdateUser(new User { Username = "no-role", UserRootDirectory = _root.Path, RoleId = _tenantB }));
        Assert.Equal(_tenantB, Repository.GetUser("no-role").RoleId);
    }

    [Fact]
    public void An_administrator_with_manage_users_only_cannot_call_the_settings_methods()
    {
        SignInAs(AdminPermissions.ManageUsers);

        Assert.NotNull(Scoped.ServerSettings);
        var settings = new ServerSettings { ListenToPort = 2022 };
        Assert.Throws<AdminAccessDeniedException>(() => Scoped.UpdateServerSettings(settings));
        Assert.Equal(2222, Repository.ServerSettings.ListenToPort);
    }

    [Fact]
    public void An_administrator_without_manage_users_sees_no_user_and_cannot_change_one()
    {
        SignInAs(AdminPermissions.ManageSettings);

        Assert.Empty(Scoped.GetAllUsers());
        Assert.Null(Scoped.GetUser("a-user"));
        Assert.Throws<AdminAccessDeniedException>(() => Scoped.AddUser(new User { Username = "x", UserRootDirectory = _root.Path }));
        Assert.Throws<AdminAccessDeniedException>(() => Scoped.RemoveUser("a-user"));
        Assert.NotNull(Repository.GetUser("a-user"));
    }

    [Fact]
    public void Without_a_login_nothing_is_readable()
    {
        SignInAs(AdminPermissions.None, name: "");

        Assert.Throws<AdminAccessDeniedException>(() => Scoped.ServerSettings);
        Assert.Empty(Scoped.GetAllUsers());
    }

    [Fact]
    public async Task A_scoped_administrator_sees_and_closes_only_the_connections_of_its_users()
    {
        SignInAsTenantA(AdminPermissions.ViewConnections | AdminPermissions.DisconnectConnections);
        var closed = new List<string>();
        ConnectionInfo Connect(string endPoint, string? user)
        {
            var connection = Registry.Register(new ConnectionRegistration(ConnectionProtocols.Sftp, endPoint, _ =>
            {
                closed.Add(endPoint);
                return Task.CompletedTask;
            }));
            if (user != null)
                Registry.SetAuthenticated(connection.Id, user, "password");
            return connection;
        }
        Connect("192.0.2.1:1", "a-user");
        var other = Connect("192.0.2.2:2", "b-user");
        Connect("192.0.2.3:3", null);
        var connections = Services.GetRequiredService<ScopedConnections>();

        var page = Render<ConnectionsPage>();

        var rows = page.FindAll(".connection-row");
        Assert.Single(rows);
        Assert.Contains("a-user", rows[0].TextContent);
        Assert.False(await connections.DisconnectAsync(other.Id, "test"));
        Assert.Empty(closed);
    }

    [Fact]
    public async Task Closing_a_connection_needs_its_own_permission()
    {
        SignInAs(AdminPermissions.ViewConnections);
        var connection = Registry.Register(new ConnectionRegistration(ConnectionProtocols.Sftp, "192.0.2.1:1", _ => Task.CompletedTask));
        Registry.SetAuthenticated(connection.Id, "a-user", "password");

        var page = Render<ConnectionsPage>();

        Assert.Single(page.FindAll(".connection-row"));
        Assert.Empty(page.FindAll(".disconnect-button"));
        await Assert.ThrowsAsync<AdminAccessDeniedException>(() =>
            Services.GetRequiredService<ScopedConnections>().DisconnectAsync(connection.Id, "test"));
        Assert.NotNull(Registry.Get(connection.Id));
    }

    [Fact]
    public async Task A_scoped_administrator_reads_only_the_audit_entries_of_its_users()
    {
        SignInAsTenantA(AdminPermissions.ViewAudit);
        foreach (var user in new[] { "a-user", "b-user", "no-role" })
            await AuditLog.AppendAsync(new AuditEntry { Category = "File", Type = "Upload", Status = "Ok", Username = user, TimestampUtc = DateTime.UtcNow }, CancellationToken.None);
        await AuditLog.AppendAsync(new AuditEntry { Category = "Provider", Type = "Update", Status = "Ok", Actor = "root", TimestampUtc = DateTime.UtcNow }, CancellationToken.None);
        var audit = Services.GetRequiredService<ScopedAuditLog>();

        var all = await audit.QueryAsync(new AuditQuery(), Xunit.TestContext.Current.CancellationToken);
        var asked = await audit.QueryAsync(new AuditQuery { Usernames = ["b-user", "a-user"] }, Xunit.TestContext.Current.CancellationToken);

        Assert.Equal(["a-user"], all.Entries.Select(e => e.Username));
        Assert.Equal(["a-user"], asked.Entries.Select(e => e.Username));
    }

    [Fact]
    public async Task The_audit_log_needs_view_audit()
    {
        SignInAs(AdminPermissions.ManageUsers);

        await Assert.ThrowsAsync<AdminAccessDeniedException>(() =>
            Services.GetRequiredService<ScopedAuditLog>().QueryAsync(new AuditQuery(), Xunit.TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task A_super_admin_creates_an_administrator_on_the_admins_page()
    {
        var page = Render<Admins>();

        page.Find("#add-admin").Click();
        page.Find("#admin-username").Change("helper");
        page.Find("#admin-password").Change("long-enough-1");
        page.Find("#admin-confirm-password").Change("long-enough-1");
        page.Find("#admin-scope").Change(_tenantA.ToString(System.Globalization.CultureInfo.InvariantCulture));
        page.Find("#perm-ManageUsers").Change(true);
        page.Find("#admin-form").Submit();

        page.WaitForAssertion(() => Assert.NotNull(AdminStore.GetAdminAsync("helper", CancellationToken.None).Result), SaveTimeout);
        var admin = (await AdminStore.GetAdminAsync("helper", CancellationToken.None))!;
        Assert.Equal(AdminPermissions.ManageUsers, admin.Permissions);
        Assert.Equal(_tenantA, admin.ScopeRoleId);
        Assert.True(admin.MustChangePassword);
        page.WaitForAssertion(() => Assert.Contains("helper", page.Find("#admin-table").TextContent));
    }

    [Fact]
    public void A_non_super_administrator_cannot_tick_permissions_it_does_not_have()
    {
        SignInAs(AdminPermissions.ManageAdmins | AdminPermissions.ManageUsers, name: "manager");
        var page = Render<Admins>();

        page.Find("#add-admin").Click();

        Assert.False(page.Find("#perm-ManageUsers").HasAttribute("disabled"));
        Assert.True(page.Find("#perm-SuperAdmin").HasAttribute("disabled"));
        Assert.True(page.Find("#perm-ManageSettings").HasAttribute("disabled"));
    }

    [Fact]
    public async Task Roles_are_created_and_users_are_added_to_them_on_the_roles_page()
    {
        var page = Render<Roles>();

        page.Find("#role-name").Change("tenant-c");
        page.Find("#role-form").Submit();
        page.WaitForAssertion(() => Assert.Contains("tenant-c", page.Find("#role-list").TextContent));

        var row = page.FindAll(".role-row").Single(r => r.TextContent.Contains("tenant-c"));
        row.QuerySelector(".select-role")!.Click();
        page.Find("#role-add-user").Change("no-role");
        page.Find("#role-add-user-button").Click();

        var roleId = (await AdminStore.ListRolesAsync(CancellationToken.None)).Single(r => r.Name == "tenant-c").Id;
        Assert.Equal(roleId, Repository.GetUser("no-role").RoleId);
        Assert.Contains("no-role", page.Find("#role-members").TextContent);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _root.Dispose();
        base.Dispose(disposing);
    }
}
