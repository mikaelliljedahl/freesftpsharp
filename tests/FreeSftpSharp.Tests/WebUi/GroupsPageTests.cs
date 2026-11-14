using Bunit;
using FreeSftpSharp.Tests.Infrastructure;
using FreeSftpSharp.Tests.Settings;
using FxSshSftpServer.Components.Pages;
using FxSshSftpServer.Security;
using Microsoft.Extensions.DependencyInjection;
using SshServer.Interfaces;
using SshServer.Interfaces.Admins;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Groups;
using SshServer.Interfaces.Permissions;

namespace FreeSftpSharp.Tests.WebUi;

/// <summary>
/// The groups page and the groups and lifecycle fields of the users page (issue #61, bUnit), and the scope of the
/// groups in the services behind the pages.
/// </summary>
public sealed class GroupsPageTests : AdminUiComponentContext
{
    private static readonly TimeSpan SaveTimeout = TimeSpan.FromSeconds(15);

    private readonly TempDirectory _root = new();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _root.Dispose();
        base.Dispose(disposing);
    }

    private Group AddGroup(string name, int? roleId = null, Action<Group>? configure = null)
    {
        var group = new Group { Name = name, RoleId = roleId };
        configure?.Invoke(group);
        Assert.True(Repository.AddGroup(group));
        return group;
    }

    private void AddUser(string name, Action<User>? configure = null)
    {
        var user = new User { Username = name, UserRootDirectory = _root.Path, HashedPassword = TestCredentials.HashPassword("secret-password"), WhitelistedIps = [] };
        configure?.Invoke(user);
        Repository.AddUser(user);
    }

    private int AddRole(string name)
    {
        var role = new Role { Name = name };
        Assert.True(AdminStore.AddRoleAsync(role, CancellationToken.None).GetAwaiter().GetResult());
        return role.Id;
    }

    [Fact]
    public void A_group_is_created_with_permissions_login_methods_and_networks()
    {
        var page = Render<Groups>();

        page.Click("#add-group");
        page.Change("#group-name", "readers");
        page.Change("#group-description", "read only");
        page.Change("#group-set-permissions", true);
        foreach (var column in FxSshSftpServer.Models.PermissionRow.Columns.Where(c => c.Flag is not (FilePermissions.List or FilePermissions.Download)))
            page.Change($"#permission-0-{column.Flag}", false);
        page.Change("#group-restrict-methods", true);
        page.Change("#group-allow-password", false);
        page.Change("#group-allowed-ips", "10.0.0.0/8");
        page.Submit("#group-form");

        var group = Assert.Single(Repository.GetGroups());
        Assert.Equal(("readers", "read only"), (group.Name, group.Description));
        Assert.Equal(new Dictionary<string, FilePermissions> { ["/"] = FilePermissions.List | FilePermissions.Download }, group.Permissions);
        Assert.Null(group.PathFilters);
        Assert.Null(group.Storage);
        Assert.Equal(AuthMethods.PublicKey | AuthMethods.KeyboardInteractive, group.AllowedAuthMethods);
        Assert.Equal(["10.0.0.0/8"], group.AllowedIps);
        Assert.Contains("readers", page.Find("#group-table").TextContent);
    }

    [Fact]
    public void A_group_saves_its_quota_and_bandwidth_defaults()
    {
        var page = Render<Groups>();

        page.Click("#add-group");
        page.Change("#group-name", "limited");
        page.Change("#quota-size", "2");
        page.Change("#quota-total", "100");
        page.Change("#bandwidth-upload", "128");
        page.Submit("#group-form");

        var group = Assert.Single(Repository.GetGroups());
        Assert.Equal(2L * 1024 * 1024, group.DiskQuota!.MaxSizeBytes);
        Assert.Equal(100L * 1024 * 1024, group.TransferQuota!.MaxTotalBytes);
        Assert.Equal(128, group.Bandwidth!.UploadKiBPerSecond);

        page.Click(".edit-group");
        Assert.Equal("2", page.Find("#quota-size").GetAttribute("value"));
    }

    [Fact]
    public void A_new_group_sets_nothing_and_a_bad_network_is_refused()
    {
        var page = Render<Groups>();

        page.Click("#add-group");
        page.Change("#group-name", "empty");
        page.Change("#group-allowed-ips", "10.0.0.0/40");
        page.Submit("#group-form");

        Assert.Contains("Not a valid network: 10.0.0.0/40", page.Find("#group-problems").TextContent);
        Assert.Empty(Repository.GetGroups());

        page.Change("#group-allowed-ips", "");
        page.Submit("#group-form");

        var group = Assert.Single(Repository.GetGroups());
        Assert.Null(group.Permissions);
        Assert.Null(group.AllowedAuthMethods);
        Assert.Null(group.AllowedIps);
        Assert.Empty(group.VirtualFolders);
    }

    [Fact]
    public void The_group_page_shows_the_members_and_refuses_to_delete_a_group_with_members()
    {
        var group = AddGroup("sales");
        AddUser("alice", u => u.PrimaryGroupId = group.Id);
        AddUser("bob", u => u.SecondaryGroupIds = [group.Id]);
        var page = Render<Groups>();

        Assert.Equal("alice, bob", page.Find(".group-members").TextContent);
        page.Click(".delete-group");
        page.Click(".confirm-button");

        Assert.NotNull(Repository.GetGroup(group.Id));
        Assert.Contains("Remove them from the group first", Toasts.Messages.Single().Text);
    }

    [Fact]
    public void A_user_gets_groups_and_lifecycle_fields_on_the_users_page_and_inherits_the_permissions()
    {
        var readers = AddGroup("readers", configure: g => g.Permissions = new() { ["/"] = FilePermissions.List });
        var lan = AddGroup("lan", configure: g => g.AllowedIps = ["10.0.0.0/8"]);
        AddUser("carol");
        var page = Render<Users>();

        page.Click(".edit-user");
        page.Change("#primary-group", readers.Id.ToString());
        page.Change($"#secondary-group-{lan.Id}", true);
        Assert.True(page.Find("#inherit-permissions").HasAttribute("checked")); // a user without own rules takes those of the groups
        Assert.Empty(page.FindAll("#permission-table"));
        Assert.Contains("group readers", page.Find("#effective-permissions").TextContent);
        Assert.Contains("10.0.0.0/8", page.Find("#effective-networks").TextContent);
        Assert.Contains("group lan", page.Find("#effective-networks").TextContent);
        page.Change("#user-enabled", false);
        page.Change("#user-expires", "2027-01-31");
        page.Change("#user-max-sessions", "2");
        page.Change("#user-description", "contractor");
        page.Submit("#user-form");

        page.WaitForAssertion(() => Assert.Equal(readers.Id, Repository.GetUser("carol").PrimaryGroupId), SaveTimeout);
        var user = Repository.GetUser("carol");
        Assert.Equal([lan.Id], user.SecondaryGroupIds);
        Assert.Null(user.Permissions);
        Assert.Equal(UserStatus.Disabled, user.Status);
        Assert.Equal(new DateTime(2027, 1, 31, 0, 0, 0, DateTimeKind.Utc), user.ExpiresAt);
        Assert.Equal(2, user.MaxSessions);
        Assert.Equal("contractor", user.Description);
        page.WaitForAssertion(() => Assert.Contains("disabled", page.Find("#user-table").TextContent), SaveTimeout);
    }

    [Fact]
    public void A_member_with_own_permissions_keeps_them()
    {
        var readers = AddGroup("readers", configure: g => g.Permissions = new() { ["/"] = FilePermissions.List });
        AddUser("dave", u => u.Permissions = new() { ["/"] = FilePermissions.All, ["/in"] = FilePermissions.Upload });
        var page = Render<Users>();

        page.Click(".edit-user");
        page.Change("#primary-group", readers.Id.ToString());

        Assert.False(page.Find("#inherit-permissions").HasAttribute("checked"));
        Assert.Contains("user", page.Find("#effective-permissions .origin").TextContent);
        page.Submit("#user-form");

        page.WaitForAssertion(() => Assert.Equal(readers.Id, Repository.GetUser("dave").PrimaryGroupId), SaveTimeout);
        Assert.Equal(FilePermissions.Upload, Repository.GetUser("dave").Permissions!["/in"]);
    }

    [Fact]
    public void A_group_storage_template_makes_the_root_directory_optional()
    {
        var homes = AddGroup("homes", configure: g => g.Storage = new SshServer.Interfaces.Storage.StorageConfig
        {
            Provider = "local",
            Options = "{\"RootDirectory\":\"/srv/sftp/%username%\"}",
        });
        var page = Render<Users>();

        page.Click("#add-user");
        page.Change("#username", "erin");
        page.Change("#root-directory", "");
        page.Change("#primary-group", homes.Id.ToString());
        Assert.Contains("group homes", page.Find("#effective-storage").TextContent);
        page.Submit("#user-form");

        page.WaitForAssertion(() => Assert.NotNull(Repository.GetUser("erin")), SaveTimeout);
        Assert.Null(Repository.GetUser("erin").Storage);
    }

    [Fact]
    public void A_scoped_administrator_sees_creates_and_gives_only_the_groups_of_its_role()
    {
        var tenantA = AddRole("tenant-a");
        var tenantB = AddRole("tenant-b");
        var mine = AddGroup("a-group", tenantA);
        var other = AddGroup("b-group", tenantB);
        var global = AddGroup("global");
        AddUser("a-user", u => u.RoleId = tenantA);
        SignInAs(AdminPermissions.ManageUsers | AdminPermissions.ManageGroups, tenantA, "tenant-a-admin");
        var scoped = Services.GetRequiredService<AdminScopedSettingsRepository>();

        Assert.Equal(["a-group"], scoped.GetGroups().Select(g => g.Name));
        Assert.Null(scoped.GetGroup(other.Id));
        Assert.False(scoped.UpdateGroup(other));
        Assert.False(scoped.RemoveGroup(global.Id));
        var created = new Group { Name = "a-new" };
        Assert.True(scoped.AddGroup(created));
        Assert.Equal(tenantA, Repository.GetGroup(created.Id)!.RoleId);
        Assert.Throws<AdminAccessDeniedException>(() => scoped.AddGroup(new Group { Name = "b-new", RoleId = tenantB }));

        // A new object: the in-memory repository gives the stored one, so a change of it would change the stored user too.
        var user = new User { Username = "a-user", UserRootDirectory = _root.Path, RoleId = tenantA, PrimaryGroupId = global.Id };
        Assert.Throws<AdminAccessDeniedException>(() => scoped.UpdateUser(user));
        user.PrimaryGroupId = mine.Id;
        Assert.True(scoped.UpdateUser(user));
        Assert.Equal(mine.Id, Repository.GetUser("a-user").PrimaryGroupId);
    }

    [Fact]
    public void A_group_outside_the_scope_stays_when_a_scoped_administrator_saves_the_user()
    {
        var tenantA = AddRole("tenant-a");
        var global = AddGroup("global");
        var mine = AddGroup("a-group", tenantA);
        AddUser("a-user", u =>
        {
            u.RoleId = tenantA;
            u.PrimaryGroupId = global.Id;
        });
        SignInAs(AdminPermissions.ManageUsers, tenantA, "tenant-a-admin");
        var page = Render<Users>();

        page.Click(".edit-user");
        Assert.Contains("outside your scope", page.Find("#primary-group").TextContent);
        page.Change($"#secondary-group-{mine.Id}", true);
        page.Submit("#user-form");

        page.WaitForAssertion(() => Assert.Equal([mine.Id], Repository.GetUser("a-user").SecondaryGroupIds), SaveTimeout);
        Assert.Equal(global.Id, Repository.GetUser("a-user").PrimaryGroupId);
    }

    [Fact]
    public void Without_manage_groups_the_group_service_refuses_changes()
    {
        SignInAs(AdminPermissions.ManageUsers);
        var groups = Services.GetRequiredService<GroupService>();

        Assert.Throws<AdminAccessDeniedException>(() => groups.TryAdd(new Group { Name = "x" }));
        AddGroup("readable");
        Assert.Equal(["readable"], groups.List().Select(g => g.Name)); // a user manager may read them to give them
    }

    [Fact]
    public void Without_manage_groups_or_users_no_group_is_visible()
    {
        AddGroup("hidden");
        SignInAs(AdminPermissions.ViewAudit);

        Assert.Empty(Services.GetRequiredService<AdminScopedSettingsRepository>().GetGroups());
    }
}
