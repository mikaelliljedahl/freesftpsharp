using System.Net;

namespace SshServer.Interfaces;

/// <summary>An active auto-ban of a source address (see <see cref="IIpBanService"/>).</summary>
/// <param name="Address">The banned address. IPv4 clients are shown as IPv4, also when they came over IPv6.</param>
/// <param name="BannedAt">When the ban started.</param>
/// <param name="ExpiresAt">When the ban ends by itself.</param>
/// <param name="FailedAttempts">The failed logins that caused the ban.</param>
public sealed record IpBan(IPAddress Address, DateTimeOffset BannedAt, DateTimeOffset ExpiresAt, int FailedAttempts);

/// <summary>
/// The auto-bans of the SSH server (<c>ServerSettings.MaxLoginAttemptsBeforeBan</c>). The bans are kept in memory
/// only, so a restart lifts them; with <c>Cluster:Enabled</c> they are shared through the <see cref="IIpBanStore"/>.
/// The admin UI uses this service to list and lift bans.
/// </summary>
public interface IIpBanService
{
    /// <summary>The bans that have not expired.</summary>
    IReadOnlyList<IpBan> GetActiveBans();

    /// <summary>True when the address is banned now.</summary>
    bool IsBanned(IPAddress address);

    /// <summary>Lifts the ban of the address and forgets its failed logins. False when it was not banned.</summary>
    bool Unban(IPAddress address);
}

/// <summary>
/// The shared bans of several nodes (issue #75, <c>Cluster:Enabled</c>): a ban of one node is refused on every node.
/// The table BannedIps of the settings database. The failed logins are still counted per node.
/// </summary>
public interface IIpBanStore
{
    /// <summary>Adds or replaces the ban of its address.</summary>
    Task AddAsync(IpBan ban, CancellationToken ct);

    /// <summary>The bans that end after <paramref name="now"/>.</summary>
    Task<IReadOnlyList<IpBan>> ListActiveAsync(DateTimeOffset now, CancellationToken ct);

    Task RemoveAsync(IPAddress address, CancellationToken ct);

    Task<int> RemoveExpiredAsync(DateTimeOffset now, CancellationToken ct);
}
