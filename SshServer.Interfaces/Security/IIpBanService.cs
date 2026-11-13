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
/// only, so a restart lifts them. The admin UI uses this service to list and lift bans.
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
