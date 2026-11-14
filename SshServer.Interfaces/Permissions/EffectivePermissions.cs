namespace SshServer.Interfaces.Permissions;

/// <summary>
/// The permissions and path filters that apply to one user, from <see cref="Users.IEffectiveUserSettingsService"/>. The keys
/// are normalized virtual directories (<see cref="Storage.VirtualPath.Normalize"/>); "/" is always present.
/// </summary>
public sealed class EffectivePermissions
{
    /// <summary>Full access everywhere and no filters: the default of every user.</summary>
    public static EffectivePermissions Unrestricted { get; } = new(
        new Dictionary<string, FilePermissions> { [Storage.VirtualPath.Root] = FilePermissions.All },
        new Dictionary<string, PathFilter>());

    public EffectivePermissions(IReadOnlyDictionary<string, FilePermissions> permissions, IReadOnlyDictionary<string, PathFilter> filters)
    {
        if (!permissions.ContainsKey(Storage.VirtualPath.Root))
            throw new ArgumentException("The permissions must have an entry for \"/\".", nameof(permissions));
        Permissions = permissions;
        Filters = filters;
    }

    /// <summary>The permissions per virtual directory.</summary>
    public IReadOnlyDictionary<string, FilePermissions> Permissions { get; }

    /// <summary>The path filters per virtual directory; directories without filter are not in it.</summary>
    public IReadOnlyDictionary<string, PathFilter> Filters { get; }

    /// <summary>True when the user may do everything everywhere and no filter applies.</summary>
    public bool IsUnrestricted =>
        Permissions.All(p => p.Value == FilePermissions.All) && Filters.Values.All(f => f.IsEmpty);

    /// <summary>
    /// These permissions limited to <paramref name="mask"/> in every directory (the intersection with "everything in
    /// <paramref name="mask"/> everywhere"); the path filters stay. A share link (#70) uses the permissions of its owner limited
    /// to its scope.
    /// </summary>
    public EffectivePermissions Restrict(FilePermissions mask) =>
        new(Permissions.ToDictionary(p => p.Key, p => p.Value & mask, StringComparer.Ordinal), Filters);
}
