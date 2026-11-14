using SshServer.Interfaces.Authentication;
using SshServer.Interfaces.Net;
using SshServer.Interfaces.Permissions;

namespace SshServer.Interfaces.Groups;

/// <summary>
/// The application service for groups (issue #61), used by the admin UI and later the REST API (#67): the groups, their
/// members, and the rules for names, settings and memberships. The admin UI gives it the scoped repository of the
/// signed-in administrator, which checks the permission and the scope itself.
/// </summary>
public sealed class GroupService
{
    public const int MaximumNameLength = 100;

    private readonly ISettingsRepository _repository;

    public GroupService(ISettingsRepository repository)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
    }

    public IReadOnlyList<Group> List() => _repository.GetGroups();

    public Group? Get(int id) => _repository.GetGroup(id);

    /// <summary>The names of the users that have the group as primary or secondary group.</summary>
    public IReadOnlyList<string> MembersOf(int id) => _repository.GetAllUsers()
        .Where(u => IsMember(u, id))
        .Select(u => u.Username)
        .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
        .ToList();

    /// <summary>Adds a group. False when the name is already used (without case).</summary>
    public bool TryAdd(Group group)
    {
        group.Name = group.Name.Trim();
        if (_repository.GetGroups().Any(g => string.Equals(g.Name, group.Name, StringComparison.OrdinalIgnoreCase)))
            return false;
        return _repository.AddGroup(group);
    }

    /// <summary>Saves a group. False when it does not exist or another group has the name.</summary>
    public bool TryUpdate(Group group)
    {
        group.Name = group.Name.Trim();
        if (_repository.GetGroups().Any(g => g.Id != group.Id && string.Equals(g.Name, group.Name, StringComparison.OrdinalIgnoreCase)))
            return false;
        return _repository.UpdateGroup(group);
    }

    /// <summary>
    /// Removes a group without members. Throws <see cref="GroupAdministrationException"/> when users are still members:
    /// remove them first, so that no user loses its settings without the administrator seeing it.
    /// </summary>
    public bool Remove(int id)
    {
        var members = MembersOf(id);
        if (members.Count > 0)
            throw new GroupAdministrationException(
                $"The group has {members.Count} member(s): {string.Join(", ", members)}. Remove them from the group first.");
        return _repository.RemoveGroup(id);
    }

    /// <summary>An error text for the name, or null when it is valid.</summary>
    public static string? ValidateName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return "Enter a name.";
        if (name.Trim().Length > MaximumNameLength)
            return $"The name can have at most {MaximumNameLength} characters.";
        return null;
    }

    /// <summary>The problems of the settings of a group (not the storage and the mounts: the storage services check them).</summary>
    public static IReadOnlyList<string> Validate(Group group)
    {
        var problems = new List<string>();
        if (ValidateName(group.Name) is { } name)
            problems.Add(name);
        problems.AddRange(PermissionRulesValidator.Validate(group.Permissions, group.PathFilters));
        if (group.AllowedAuthMethods is { } methods)
            problems.AddRange(AuthMethodRules.Validate(methods, null));
        var invalid = CidrNotation.FindInvalid(group.AllowedIps ?? []);
        if (invalid.Count > 0)
            problems.Add($"Not a valid network: {string.Join(", ", invalid)}.");
        return problems;
    }

    /// <summary>The problems of the groups of a user: every group exists, and the primary group is not a secondary group too.</summary>
    public IReadOnlyList<string> ValidateMembership(User user)
    {
        var problems = new List<string>();
        var existing = _repository.GetGroups().Select(g => g.Id).ToHashSet();
        if (user.PrimaryGroupId is { } primary && !existing.Contains(primary))
            problems.Add("The primary group does not exist.");
        var secondary = user.SecondaryGroupIds ?? [];
        if (secondary.Any(id => !existing.Contains(id)))
            problems.Add("A secondary group does not exist.");
        if (user.PrimaryGroupId is { } p && secondary.Contains(p))
            problems.Add("The primary group cannot be a secondary group too.");
        if (secondary.Distinct().Count() != secondary.Count)
            problems.Add("A secondary group is selected twice.");
        return problems;
    }

    /// <summary>True when the user has the group as primary or secondary group.</summary>
    public static bool IsMember(User user, int groupId) =>
        user.PrimaryGroupId == groupId || (user.SecondaryGroupIds ?? []).Contains(groupId);
}

/// <summary>A group operation that is not possible. The message is meant for the administrator.</summary>
public sealed class GroupAdministrationException : Exception
{
    public GroupAdministrationException(string message) : base(message)
    {
    }
}
