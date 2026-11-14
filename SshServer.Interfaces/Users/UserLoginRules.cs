using SshServer.Interfaces.Authentication;

namespace SshServer.Interfaces.Users;

/// <summary>
/// The lifecycle rules of a login (issue #61): status, expiry, password age and the session limit. Every protocol asks
/// them before it checks the credential, and refuses the login in the same way (and time) as a wrong credential. The
/// returned reason is for the log and the audit events, never for the client.
/// </summary>
public static class UserLoginRules
{
    /// <summary>
    /// Why <paramref name="user"/> may not log in with <paramref name="method"/> at <paramref name="utcNow"/>, or null
    /// when it may. <paramref name="passwordMaxAgeDays"/> is <see cref="ServerSettings.PasswordMaxAgeDays"/>.
    /// </summary>
    public static string? Refusal(User user, AuthMethods method, DateTime utcNow, int passwordMaxAgeDays)
    {
        ArgumentNullException.ThrowIfNull(user);
        if (user.Status != UserStatus.Enabled)
            return "the user is disabled";
        if (IsExpired(user, utcNow))
            return $"the user expired at {user.ExpiresAt:yyyy-MM-dd HH:mm} UTC";
        if (method == AuthMethods.Password && IsPasswordExpired(user, utcNow, passwordMaxAgeDays))
            return $"the password is older than {passwordMaxAgeDays} days";
        return null;
    }

    /// <summary>Why another session is refused when the user has <paramref name="openSessions"/> others, or null.</summary>
    public static string? SessionLimitRefusal(User user, int openSessions)
    {
        ArgumentNullException.ThrowIfNull(user);
        return user.MaxSessions > 0 && openSessions >= user.MaxSessions ? SessionLimitReason(user.MaxSessions) : null;
    }

    /// <summary>The reason of a login that the session limit refuses.</summary>
    public static string SessionLimitReason(int maxSessions) => $"the user has the maximum of {maxSessions} session(s) open";

    /// <summary>True when <see cref="User.ExpiresAt"/> is reached.</summary>
    public static bool IsExpired(User user, DateTime utcNow) => user.ExpiresAt is { } expires && utcNow >= ToUtc(expires);

    /// <summary>
    /// True when the user has a password that was set more than <paramref name="maxAgeDays"/> days ago. A password with
    /// an unknown time (<see cref="User.PasswordChangedAt"/> null) does not expire. 0 days: no password expires.
    /// </summary>
    public static bool IsPasswordExpired(User user, DateTime utcNow, int maxAgeDays) =>
        maxAgeDays > 0
        && !string.IsNullOrEmpty(user.HashedPassword)
        && user.PasswordChangedAt is { } changed
        && utcNow >= ToUtc(changed).AddDays(maxAgeDays);

    // The database gives the times back without a kind; they are stored as UTC.
    private static DateTime ToUtc(DateTime value) =>
        value.Kind == DateTimeKind.Local ? value.ToUniversalTime() : DateTime.SpecifyKind(value, DateTimeKind.Utc);
}
