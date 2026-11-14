using System.Text.Json;
using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Groups;
using SshServer.Interfaces.Permissions;
using SshServer.Interfaces.Storage;

namespace SshServer.Interfaces.Users;

/// <summary>
/// Resolves the settings of a user with one rule (issue #61): the user's own value, else the value of the primary
/// group, else the values of the secondary groups in their order, else the server default.
/// <list type="table">
/// <listheader><term>Setting</term><description>"Not set" means</description></listheader>
/// <item><term>Permissions, path filters</term><description>null or empty. The first source that has them gives all of
/// them (they are not mixed path by path), so a group can never widen or narrow a user that has its own.</description></item>
/// <item><term>Storage</term><description>null. The template of a group gets the user name for <c>%username%</c>.</description></item>
/// <item><term>Virtual folders</term><description>Added up: the user's mounts, then each group's mounts at a path that
/// is still free.</description></item>
/// <item><term>Login methods</term><description>all methods (the default of a user); null for a group.</description></item>
/// <item><term>Allowed networks</term><description>the IP whitelist of the user is off or empty; null or empty for a group.</description></item>
/// </list>
/// A group that does not exist (any more) is skipped. Without a repository there are no groups.
/// </summary>
public sealed class EffectiveUserSettingsService : IEffectiveUserSettingsService
{
    private readonly ISettingsRepository? _repository;

    /// <param name="repository">The settings, for the groups. Null: no groups.</param>
    public EffectiveUserSettingsService(ISettingsRepository? repository = null)
    {
        _repository = repository;
    }

    public EffectiveUserSettings Resolve(User user)
    {
        ArgumentNullException.ThrowIfNull(user);
        var groups = GroupsOf(user);

        var (permissionValues, permissionsOrigin) = First(user, groups,
            u => u.Permissions is { Count: > 0 } p ? p : null,
            g => g.Permissions is { Count: > 0 } p ? p : null);
        var (filterValues, filtersOrigin) = First(user, groups,
            u => HasFilters(u.PathFilters) ? u.PathFilters : null,
            g => HasFilters(g.PathFilters) ? g.PathFilters : null);

        var (storageTemplate, storageOrigin) = First(user, groups, u => u.Storage, g => g.Storage);
        StorageConfig? storage = null;
        string? storageProblem = null;
        if (storageTemplate != null)
        {
            try
            {
                storage = storageOrigin.IsInherited ? StorageTemplate.Apply(storageTemplate, user.Username) : storageTemplate;
            }
            catch (Exception ex) when (ex is ArgumentException or JsonException)
            {
                storageProblem = $"The storage template of {storageOrigin}: {ex.Message}";
            }
        }

        var (methods, methodsOrigin) = FirstValue(user, groups,
            u => u.AllowedAuthMethods != AuthMethods.All ? u.AllowedAuthMethods : (AuthMethods?)null,
            g => g.AllowedAuthMethods);
        var (ips, ipsOrigin) = First(user, groups,
            u => u.OnlyWhitelistedIps && u.WhitelistedIps is { Count: > 0 } w ? w : null,
            g => g.AllowedIps is { Count: > 0 } a ? a : null);

        return new EffectiveUserSettings
        {
            User = user,
            Groups = groups.Select(g => g.Group).ToList(),
            Permissions = ToPermissions(permissionValues, filterValues),
            PermissionsOrigin = permissionsOrigin,
            PathFiltersOrigin = filtersOrigin,
            Storage = storage,
            StorageOrigin = storageOrigin,
            StorageProblem = storageProblem,
            VirtualFolders = Mounts(user, groups),
            AllowedAuthMethods = methods ?? AuthMethods.All,
            AllowedAuthMethodsOrigin = methodsOrigin,
            AllowedIps = ips?.ToList() ?? [],
            AllowedIpsOrigin = ipsOrigin,
        };
    }

    /// <summary>The existing groups of the user with their origin, primary first; a group is used once.</summary>
    private List<(Group Group, SettingOrigin Origin)> GroupsOf(User user)
    {
        var result = new List<(Group, SettingOrigin)>();
        if (_repository == null)
            return result;
        var seen = new HashSet<int>();
        if (user.PrimaryGroupId is { } primaryId && seen.Add(primaryId) && _repository.GetGroup(primaryId) is { } primary)
            result.Add((primary, new SettingOrigin(SettingSource.PrimaryGroup, primary.Name)));
        foreach (var id in user.SecondaryGroupIds ?? [])
        {
            if (seen.Add(id) && _repository.GetGroup(id) is { } group)
                result.Add((group, new SettingOrigin(SettingSource.SecondaryGroup, group.Name)));
        }
        return result;
    }

    /// <summary>The value of the first source that sets it: the user, then the groups in order; else null from the default.</summary>
    private static (T? Value, SettingOrigin Origin) First<T>(User user, List<(Group Group, SettingOrigin Origin)> groups,
        Func<User, T?> ofUser, Func<Group, T?> ofGroup) where T : class
    {
        if (ofUser(user) is { } own)
            return (own, SettingOrigin.User);
        foreach (var (group, origin) in groups)
        {
            if (ofGroup(group) is { } value)
                return (value, origin);
        }
        return (null, SettingOrigin.Default);
    }

    private static (T? Value, SettingOrigin Origin) FirstValue<T>(User user, List<(Group Group, SettingOrigin Origin)> groups,
        Func<User, T?> ofUser, Func<Group, T?> ofGroup) where T : struct
    {
        if (ofUser(user) is { } own)
            return (own, SettingOrigin.User);
        foreach (var (group, origin) in groups)
        {
            if (ofGroup(group) is { } value)
                return (value, origin);
        }
        return (null, SettingOrigin.Default);
    }

    private static bool HasFilters(Dictionary<string, PathFilter>? filters) =>
        filters != null && filters.Values.Any(f => f is { IsEmpty: false });

    /// <summary>
    /// The normalized rules. No entry for "/" means <see cref="FilePermissions.All"/> at the root (also for a user stored
    /// before per-path permissions existed).
    /// </summary>
    private static EffectivePermissions ToPermissions(Dictionary<string, FilePermissions>? values, Dictionary<string, PathFilter>? filterValues)
    {
        var permissions = new Dictionary<string, FilePermissions>(StringComparer.Ordinal);
        foreach (var (path, value) in values ?? [])
            permissions[VirtualPath.Normalize(path)] = value & FilePermissions.All;
        permissions.TryAdd(VirtualPath.Root, FilePermissions.All);

        var filters = new Dictionary<string, PathFilter>(StringComparer.Ordinal);
        foreach (var (path, filter) in filterValues ?? [])
        {
            if (filter is { IsEmpty: false })
                filters[VirtualPath.Normalize(path)] = filter;
        }

        return permissions.Count == 1 && permissions[VirtualPath.Root] == FilePermissions.All && filters.Count == 0
            ? EffectivePermissions.Unrestricted
            : new EffectivePermissions(permissions, filters);
    }

    /// <summary>The user's mounts, then the mounts of each group whose path is still free (paths compared without case).</summary>
    private static List<EffectiveMount> Mounts(User user, List<(Group Group, SettingOrigin Origin)> groups)
    {
        var result = new List<EffectiveMount>();
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Add(IEnumerable<VirtualFolderMount>? mounts, SettingOrigin origin)
        {
            foreach (var mount in mounts ?? [])
            {
                var path = VirtualPath.Normalize(mount.MountPath);
                if (path != VirtualPath.Root && paths.Add(path))
                    result.Add(new EffectiveMount(mount.VirtualFolderId, path, origin));
            }
        }

        Add(user.VirtualFolders, SettingOrigin.User);
        foreach (var (group, origin) in groups)
            Add(group.VirtualFolders, origin);
        return result;
    }
}
