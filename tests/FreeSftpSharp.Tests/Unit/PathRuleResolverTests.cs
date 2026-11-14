using SshServer.Interfaces;
using SshServer.Interfaces.Permissions;

namespace FreeSftpSharp.Tests.Unit;

/// <summary>
/// <see cref="EffectivePermissionsService"/> and <see cref="PathRuleResolver"/>: the longest matching directory wins,
/// "/" defaults to All, and paths are compared like the storage compares them (issue #59).
/// </summary>
public sealed class PathRuleResolverTests
{
    private static readonly EffectivePermissionsService Service = new();

    private static PathRuleResolver Resolver(Dictionary<string, FilePermissions>? permissions, Dictionary<string, PathFilter>? filters = null, bool caseInsensitive = false)
        => new(Service.Resolve(new User { Username = "u", Permissions = permissions, PathFilters = filters }), caseInsensitive);

    [Fact]
    public void A_new_user_has_all_permissions_at_the_root_and_is_unrestricted()
    {
        var user = new User { Username = "u" };

        Assert.Equal(FilePermissions.All, user.Permissions!["/"]);
        Assert.True(Service.Resolve(user).IsUnrestricted);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void A_user_without_permissions_or_without_a_root_entry_has_all_at_the_root(bool withOtherEntry)
    {
        var permissions = withOtherEntry ? new Dictionary<string, FilePermissions> { ["/in"] = FilePermissions.Upload } : null;

        var resolver = Resolver(permissions);

        Assert.Equal(FilePermissions.All, resolver.PermissionsOf("/"));
        Assert.Equal(FilePermissions.All, resolver.PermissionsOf("/other/deep"));
        Assert.Equal(withOtherEntry ? FilePermissions.Upload : FilePermissions.All, resolver.PermissionsOf("/in"));
    }

    [Theory]
    [InlineData("/", FilePermissions.List)]
    [InlineData("/other", FilePermissions.List)]
    [InlineData("/incoming", FilePermissions.Upload)]
    [InlineData("/incoming/x", FilePermissions.Upload)]
    [InlineData("/incoming/sub", FilePermissions.All)]
    [InlineData("/incoming/sub/deeper", FilePermissions.All)]
    [InlineData("/incoming/subway", FilePermissions.Upload)] // a prefix of the name is not the directory
    [InlineData("/incomingx", FilePermissions.List)]
    [InlineData("/incoming/sub/../x", FilePermissions.Upload)] // normalized first
    [InlineData("incoming\\sub", FilePermissions.All)]
    public void The_longest_matching_directory_wins(string directory, FilePermissions expected)
    {
        var resolver = Resolver(new()
        {
            ["/"] = FilePermissions.List,
            ["/incoming"] = FilePermissions.Upload,
            ["/incoming/sub"] = FilePermissions.All,
        });

        Assert.Equal(expected, resolver.PermissionsOf(directory));
    }

    [Fact]
    public void Keys_are_normalized()
    {
        var resolver = Resolver(new() { ["/"] = FilePermissions.None, ["/a/b/"] = FilePermissions.Download, ["\\c\\.\\d"] = FilePermissions.List });

        Assert.Equal(FilePermissions.Download, resolver.PermissionsOf("/a/b/c"));
        Assert.Equal(FilePermissions.List, resolver.PermissionsOf("/c/d"));
    }

    [Theory]
    [InlineData("/INCOMING")]
    [InlineData("/Incoming/x")]
    [InlineData("/incoming./x")]
    [InlineData("/incoming /x")]
    public void A_case_insensitive_storage_matches_the_same_directory_in_another_spelling(string directory)
    {
        var permissions = new Dictionary<string, FilePermissions> { ["/"] = FilePermissions.All, ["/incoming"] = FilePermissions.Upload };

        Assert.Equal(FilePermissions.Upload, Resolver(permissions, caseInsensitive: true).PermissionsOf(directory));
        Assert.Equal(FilePermissions.All, Resolver(permissions, caseInsensitive: false).PermissionsOf(directory));
    }

    [Fact]
    public void The_filter_with_the_longest_matching_directory_wins()
    {
        var resolver = Resolver(null, new()
        {
            ["/"] = new PathFilter { DeniedPatterns = ["*.exe"] },
            ["/data"] = new PathFilter { AllowedPatterns = ["*.csv"] },
        });

        Assert.False(resolver.IsFileNameAllowed("/setup.exe"));
        Assert.False(resolver.IsFileNameAllowed("/a/SETUP.EXE")); // patterns ignore case
        Assert.True(resolver.IsFileNameAllowed("/a/readme.txt"));
        Assert.True(resolver.IsFileNameAllowed("/data/x/report.CSV"));
        Assert.False(resolver.IsFileNameAllowed("/data/readme.txt"));
        Assert.True(resolver.IsFileNameAllowed("/data/setup.exe.csv"));
    }

    [Fact]
    public void A_denied_pattern_wins_over_an_allowed_one()
    {
        var resolver = Resolver(null, new() { ["/"] = new PathFilter { AllowedPatterns = ["*.csv"], DeniedPatterns = ["secret*"] } });

        Assert.True(resolver.IsFileNameAllowed("/report.csv"));
        Assert.False(resolver.IsFileNameAllowed("/secret.csv"));
    }

    [Theory]
    [InlineData("/.git", true)]
    [InlineData("/.git/config", true)]
    [InlineData("/a/.git/config", true)]
    [InlineData("/a/b.tmp", true)]
    [InlineData("/a/b.TMP", true)]
    [InlineData("/a/b.txt", false)]
    [InlineData("/a.tmp/b.txt", true)]
    [InlineData("/", false)]
    public void A_hidden_pattern_hides_the_entry_and_everything_below_it(string path, bool hidden)
    {
        var resolver = Resolver(null, new() { ["/"] = new PathFilter { HiddenPatterns = [".git", "*.tmp"] } });

        Assert.Equal(hidden, resolver.IsHidden(path));
    }

    [Fact]
    public void A_hidden_name_with_a_trailing_dot_is_hidden_on_a_case_insensitive_storage()
    {
        var filters = new Dictionary<string, PathFilter> { ["/"] = new PathFilter { HiddenPatterns = ["secret"], DeniedPatterns = ["*.exe"] } };

        Assert.True(Resolver(null, filters, caseInsensitive: true).IsHidden("/SECRET./x"));
        Assert.False(Resolver(null, filters, caseInsensitive: true).IsFileNameAllowed("/a.exe."));
        Assert.False(Resolver(null, filters, caseInsensitive: false).IsHidden("/secret./x"));
    }

    [Theory]
    [InlineData("/a", true)]
    [InlineData("/a/b", true)]
    [InlineData("/a/b/c", false)]
    [InlineData("/x", true)]
    [InlineData("/y", false)]
    [InlineData("/", true)]
    public void Rules_at_or_below_a_path_are_found(string path, bool expected)
    {
        var resolver = Resolver(new() { ["/"] = FilePermissions.All, ["/a/b"] = FilePermissions.List }, new() { ["/x/y"] = new PathFilter { HiddenPatterns = ["z"] } });

        Assert.Equal(expected, resolver.HasRulesAtOrBelow(path));
    }

    [Fact]
    public void A_user_with_only_full_permissions_and_empty_filters_is_unrestricted()
    {
        var user = new User
        {
            Username = "u",
            Permissions = new() { ["/"] = FilePermissions.All, ["/a"] = FilePermissions.All },
            PathFilters = new() { ["/b"] = new PathFilter() },
        };

        Assert.True(Service.Resolve(user).IsUnrestricted);
        user.Permissions["/a"] = FilePermissions.All & ~FilePermissions.Delete;
        Assert.False(Service.Resolve(user).IsUnrestricted);
    }

    [Fact]
    public void The_validator_needs_a_root_entry_and_paths_that_start_with_a_slash()
    {
        Assert.Empty(PermissionRulesValidator.Validate(new Dictionary<string, FilePermissions> { ["/"] = FilePermissions.All }, null));
        Assert.Contains(PermissionRulesValidator.Validate(new Dictionary<string, FilePermissions> { ["/a"] = FilePermissions.All }, null),
            p => p.Contains("\"/\""));
        Assert.Contains(PermissionRulesValidator.Validate(new Dictionary<string, FilePermissions> { ["/"] = FilePermissions.All, ["a"] = FilePermissions.All }, null),
            p => p.Contains("must start with"));
        Assert.Contains(PermissionRulesValidator.Validate(new Dictionary<string, FilePermissions> { ["/"] = FilePermissions.All, ["/a/"] = FilePermissions.All, ["/a"] = FilePermissions.List }, null),
            p => p.Contains("twice"));
        Assert.Contains(PermissionRulesValidator.Validate(null, new Dictionary<string, PathFilter> { ["/"] = new PathFilter { DeniedPatterns = ["a/b"] } }),
            p => p.Contains("cannot have"));
    }
}
