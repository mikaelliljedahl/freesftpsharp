using SshServer.Interfaces.Storage;

namespace SshServer.Interfaces.Permissions;

/// <summary>
/// The permissions of a user are its own <see cref="User.Permissions"/> and <see cref="User.PathFilters"/>. The paths
/// are normalized. A user without an entry for "/" (for example one stored before per-path permissions existed) has
/// <see cref="FilePermissions.All"/> at the root.
/// </summary>
public sealed class EffectivePermissionsService : IEffectivePermissionsService
{
    public EffectivePermissions Resolve(User user)
    {
        var permissions = new Dictionary<string, FilePermissions>(StringComparer.Ordinal);
        foreach (var (path, value) in user.Permissions ?? new Dictionary<string, FilePermissions>())
            permissions[VirtualPath.Normalize(path)] = value & FilePermissions.All;
        permissions.TryAdd(VirtualPath.Root, FilePermissions.All);

        var filters = new Dictionary<string, PathFilter>(StringComparer.Ordinal);
        foreach (var (path, filter) in user.PathFilters ?? new Dictionary<string, PathFilter>())
        {
            if (filter is { IsEmpty: false })
                filters[VirtualPath.Normalize(path)] = filter;
        }

        return permissions.Count == 1 && permissions[VirtualPath.Root] == FilePermissions.All && filters.Count == 0
            ? EffectivePermissions.Unrestricted
            : new EffectivePermissions(permissions, filters);
    }
}
