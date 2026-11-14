using System.Text.Json;
using FreeSftpSharp.Tests.Infrastructure;
using SshServer.Interfaces;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Groups;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;
using SshServer.Interfaces.Users;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>
/// <see cref="EffectiveUserSettingsService"/> (issue #61): the user's own value, else the primary group, else the
/// secondary groups in order, else the server default, for every setting a group can set.
/// </summary>
public sealed class EffectiveUserSettingsTests
{
    private readonly InMemorySettingsRepository _repository = new(new ServerSettings());
    private readonly EffectiveUserSettingsService _service;

    public EffectiveUserSettingsTests()
    {
        _service = new EffectiveUserSettingsService(_repository);
    }

    private Group AddGroup(string name, Action<Group>? configure = null)
    {
        var group = new Group { Name = name };
        configure?.Invoke(group);
        Assert.True(_repository.AddGroup(group));
        return group;
    }

    private static Dictionary<string, FilePermissions> ReadOnly() => new() { ["/"] = FilePermissions.List | FilePermissions.Download };

    [Fact]
    public void A_user_without_groups_and_settings_gets_the_server_defaults()
    {
        var settings = _service.Resolve(new User { Username = "u" });

        Assert.Same(EffectivePermissions.Unrestricted, settings.Permissions);
        Assert.Equal(SettingOrigin.Default, settings.PermissionsOrigin);
        Assert.Null(settings.Storage);
        Assert.Equal(SettingOrigin.Default, settings.StorageOrigin);
        Assert.Empty(settings.VirtualFolders);
        Assert.Equal(AuthMethods.All, settings.AllowedAuthMethods);
        Assert.Empty(settings.AllowedIps);
        Assert.Empty(settings.Groups);
    }

    [Fact]
    public void A_user_without_permissions_inherits_the_primary_group_and_loses_them_without_it()
    {
        var group = AddGroup("readers", g => g.Permissions = ReadOnly());
        var user = new User { Username = "u", PrimaryGroupId = group.Id };

        var inherited = _service.Resolve(user);
        Assert.Equal(FilePermissions.List | FilePermissions.Download, inherited.Permissions.Permissions["/"]);
        Assert.Equal(new SettingOrigin(SettingSource.PrimaryGroup, "readers"), inherited.PermissionsOrigin);
        Assert.Equal("group readers", inherited.PermissionsOrigin.ToString());

        user.PrimaryGroupId = null;
        Assert.True(_service.Resolve(user).Permissions.IsUnrestricted);
    }

    [Fact]
    public void The_own_permissions_of_a_user_win_as_a_whole()
    {
        var group = AddGroup("readers", g => g.Permissions = new() { ["/"] = FilePermissions.List, ["/private"] = FilePermissions.None });
        var user = new User { Username = "u", PrimaryGroupId = group.Id, Permissions = new() { ["/"] = FilePermissions.All } };

        var settings = _service.Resolve(user);

        Assert.True(settings.Permissions.IsUnrestricted); // "/private" of the group is not mixed in
        Assert.Equal(SettingOrigin.User, settings.PermissionsOrigin);
    }

    [Fact]
    public void The_primary_group_comes_before_the_secondary_groups_and_those_in_their_order()
    {
        var first = AddGroup("first", g => g.Permissions = new() { ["/"] = FilePermissions.List });
        var second = AddGroup("second", g =>
        {
            g.Permissions = new() { ["/"] = FilePermissions.Download };
            g.AllowedAuthMethods = AuthMethods.PublicKey;
        });
        var primary = AddGroup("primary", g => g.AllowedIps = ["10.0.0.0/8"]);
        var user = new User { Username = "u", PrimaryGroupId = primary.Id, SecondaryGroupIds = [second.Id, first.Id] };

        var settings = _service.Resolve(user);

        Assert.Equal(["primary", "second", "first"], settings.Groups.Select(g => g.Name));
        Assert.Equal(FilePermissions.Download, settings.Permissions.Permissions["/"]); // the primary group has none: the first secondary
        Assert.Equal(new SettingOrigin(SettingSource.SecondaryGroup, "second"), settings.PermissionsOrigin);
        Assert.Equal(AuthMethods.PublicKey, settings.AllowedAuthMethods);
        Assert.Equal(["10.0.0.0/8"], settings.AllowedIps);
        Assert.Equal(new SettingOrigin(SettingSource.PrimaryGroup, "primary"), settings.AllowedIpsOrigin);
    }

    [Fact]
    public void A_group_that_does_not_exist_is_skipped_and_a_group_is_used_once()
    {
        var group = AddGroup("readers", g => g.Permissions = ReadOnly());
        var user = new User { Username = "u", PrimaryGroupId = 999, SecondaryGroupIds = [group.Id, group.Id] };

        var settings = _service.Resolve(user);

        Assert.Equal(["readers"], settings.Groups.Select(g => g.Name));
        Assert.Equal(FilePermissions.List | FilePermissions.Download, settings.Permissions.Permissions["/"]);
    }

    [Fact]
    public void Path_filters_are_resolved_apart_from_the_permissions()
    {
        var group = AddGroup("filtered", g => g.PathFilters = new() { ["/"] = new PathFilter { DeniedPatterns = ["*.exe"] } });
        var user = new User { Username = "u", PrimaryGroupId = group.Id, Permissions = new() { ["/in"] = FilePermissions.Upload } };

        var settings = _service.Resolve(user);

        Assert.Equal(SettingOrigin.User, settings.PermissionsOrigin);
        Assert.Equal(FilePermissions.Upload, settings.Permissions.Permissions["/in"]);
        Assert.Equal(["*.exe"], settings.Permissions.Filters["/"].DeniedPatterns);
        Assert.Equal(new SettingOrigin(SettingSource.PrimaryGroup, "filtered"), settings.PathFiltersOrigin);

        user.PathFilters = new() { ["/"] = new PathFilter() }; // an empty filter is not set
        Assert.Equal(SettingSource.PrimaryGroup, _service.Resolve(user).PathFiltersOrigin.Source);
    }

    [Fact]
    public void The_storage_template_of_a_group_gets_the_user_name_and_the_own_storage_wins()
    {
        var template = new StorageConfig { Provider = "local", Options = JsonSerializer.Serialize(new { RootDirectory = "/srv/sftp/%USERNAME%/home" }) };
        var group = AddGroup("homes", g => g.Storage = template);
        var user = new User { Username = "alice", PrimaryGroupId = group.Id };

        var settings = _service.Resolve(user);

        Assert.Equal("local", settings.Storage!.Provider);
        Assert.Equal("/srv/sftp/alice/home", JsonDocument.Parse(settings.Storage.Options).RootElement.GetProperty("RootDirectory").GetString());
        Assert.Equal(SettingSource.PrimaryGroup, settings.StorageOrigin.Source);

        var own = new StorageConfig { Provider = "local", Options = "{\"RootDirectory\":\"/own/%username%\"}" };
        user.Storage = own;
        var withOwn = _service.Resolve(user);
        Assert.Same(own, withOwn.Storage); // the user's own storage is not a template
        Assert.Equal(SettingOrigin.User, withOwn.StorageOrigin);
    }

    [Theory]
    [InlineData("..")]
    [InlineData(".")]
    public void A_user_name_that_would_leave_the_template_folder_gives_a_storage_problem(string username)
    {
        var group = AddGroup("homes", g => g.Storage = new StorageConfig { Provider = "local", Options = "{\"RootDirectory\":\"/srv/%username%\"}" });

        var settings = _service.Resolve(new User { Username = username, PrimaryGroupId = group.Id });

        Assert.Null(settings.Storage);
        Assert.Contains("group homes", settings.StorageProblem);
    }

    [Fact]
    public void Virtual_folders_are_added_up_and_the_user_keeps_its_mount_path()
    {
        var group = AddGroup("shared", g => g.VirtualFolders =
        [
            new VirtualFolderMount { VirtualFolderId = 1, MountPath = "/shared" },
            new VirtualFolderMount { VirtualFolderId = 2, MountPath = "/Mine" },
        ]);
        var user = new User { Username = "u", PrimaryGroupId = group.Id, VirtualFolders = [new VirtualFolderMount { VirtualFolderId = 3, MountPath = "/mine" }] };

        var mounts = _service.Resolve(user).VirtualFolders;

        Assert.Equal([(3, "/mine", SettingSource.User), (1, "/shared", SettingSource.PrimaryGroup)],
            mounts.Select(m => (m.VirtualFolderId, m.MountPath, m.Origin.Source)));
    }

    [Fact]
    public void A_user_with_every_login_method_takes_the_methods_of_its_group_and_a_restricted_user_keeps_its_own()
    {
        var group = AddGroup("keys", g => g.AllowedAuthMethods = AuthMethods.PublicKey);
        var user = new User { Username = "u", PrimaryGroupId = group.Id };

        Assert.Equal(AuthMethods.PublicKey, _service.Resolve(user).AllowedAuthMethods);

        user.AllowedAuthMethods = AuthMethods.Password;
        var own = _service.Resolve(user);
        Assert.Equal(AuthMethods.Password, own.AllowedAuthMethods);
        Assert.Equal(SettingOrigin.User, own.AllowedAuthMethodsOrigin);
    }

    [Fact]
    public void The_ip_whitelist_of_the_user_wins_when_it_is_on_and_not_empty()
    {
        var group = AddGroup("lan", g => g.AllowedIps = ["10.0.0.0/8"]);
        var user = new User { Username = "u", PrimaryGroupId = group.Id, OnlyWhitelistedIps = false, WhitelistedIps = ["192.168.0.0/16"] };

        Assert.Equal(["10.0.0.0/8"], _service.Resolve(user).AllowedIps); // the whitelist of the user is off

        user.OnlyWhitelistedIps = true;
        Assert.Equal(["192.168.0.0/16"], _service.Resolve(user).AllowedIps);
    }

    [Fact]
    public void Without_a_repository_there_are_no_groups()
    {
        var settings = new EffectiveUserSettingsService().Resolve(new User { Username = "u", PrimaryGroupId = 1 });

        Assert.Empty(settings.Groups);
        Assert.True(settings.Permissions.IsUnrestricted);
    }
}
