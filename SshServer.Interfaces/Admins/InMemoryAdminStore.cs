namespace SshServer.Interfaces.Admins;

/// <summary>
/// An <see cref="IAdminStore"/> in memory: for the obsolete LiteDB settings provider (which has no admin table; the
/// configured <c>AdminAuth</c> account is imported again at every start) and for tests.
/// </summary>
public sealed class InMemoryAdminStore : IAdminStore
{
    private readonly object _lock = new();
    private readonly List<Admin> _admins = new();
    private readonly List<Role> _roles = new();
    private int _nextAdminId;
    private int _nextRoleId;

    public Task<bool> AnyAdminAsync(CancellationToken ct)
    {
        lock (_lock)
            return Task.FromResult(_admins.Count > 0);
    }

    public Task<IReadOnlyList<Admin>> ListAdminsAsync(CancellationToken ct)
    {
        lock (_lock)
            return Task.FromResult<IReadOnlyList<Admin>>(_admins.OrderBy(a => a.Id).Select(a => a.Clone()).ToList());
    }

    public Task<Admin?> GetAdminAsync(string username, CancellationToken ct)
    {
        lock (_lock)
            return Task.FromResult(FindAdmin(username)?.Clone());
    }

    public Task<bool> AddAdminAsync(Admin admin, CancellationToken ct)
    {
        lock (_lock)
        {
            if (string.IsNullOrWhiteSpace(admin.Username) || FindAdmin(admin.Username) != null)
                return Task.FromResult(false);
            admin.Id = ++_nextAdminId;
            _admins.Add(admin.Clone());
            return Task.FromResult(true);
        }
    }

    public Task<bool> UpdateAdminAsync(Admin admin, CancellationToken ct)
    {
        lock (_lock)
        {
            var index = _admins.FindIndex(a => a.Id == admin.Id);
            if (index < 0)
                return Task.FromResult(false);
            _admins[index] = admin.Clone();
            return Task.FromResult(true);
        }
    }

    public Task<bool> RemoveAdminAsync(int id, CancellationToken ct)
    {
        lock (_lock)
            return Task.FromResult(_admins.RemoveAll(a => a.Id == id) > 0);
    }

    public Task<IReadOnlyList<Role>> ListRolesAsync(CancellationToken ct)
    {
        lock (_lock)
            return Task.FromResult<IReadOnlyList<Role>>(_roles.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).Select(r => r.Clone()).ToList());
    }

    public Task<Role?> GetRoleAsync(int id, CancellationToken ct)
    {
        lock (_lock)
            return Task.FromResult(_roles.FirstOrDefault(r => r.Id == id)?.Clone());
    }

    public Task<bool> AddRoleAsync(Role role, CancellationToken ct)
    {
        lock (_lock)
        {
            if (string.IsNullOrWhiteSpace(role.Name) || _roles.Any(r => SameName(r.Name, role.Name)))
                return Task.FromResult(false);
            role.Id = ++_nextRoleId;
            _roles.Add(role.Clone());
            return Task.FromResult(true);
        }
    }

    public Task<bool> UpdateRoleAsync(Role role, CancellationToken ct)
    {
        lock (_lock)
        {
            var index = _roles.FindIndex(r => r.Id == role.Id);
            if (index < 0 || _roles.Any(r => r.Id != role.Id && SameName(r.Name, role.Name)))
                return Task.FromResult(false);
            _roles[index] = role.Clone();
            return Task.FromResult(true);
        }
    }

    public Task<bool> RemoveRoleAsync(int id, CancellationToken ct)
    {
        lock (_lock)
            return Task.FromResult(_roles.RemoveAll(r => r.Id == id) > 0);
    }

    private Admin? FindAdmin(string username) => _admins.FirstOrDefault(a => SameName(a.Username, username?.Trim() ?? ""));

    private static bool SameName(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
}
