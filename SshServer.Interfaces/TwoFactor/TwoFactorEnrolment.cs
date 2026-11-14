namespace SshServer.Interfaces.TwoFactor;

/// <summary>
/// The TOTP second factor of one subject (issue #63), as the <see cref="ITwoFactorStore"/> keeps it. It never holds a
/// plain secret: <see cref="ProtectedSecret"/> is encrypted with the data protection keys of the server, and the
/// recovery codes are PBKDF2 hashes.
/// </summary>
public sealed record TwoFactorEnrolment
{
    public required TwoFactorSubject Subject { get; init; }

    /// <summary>The TOTP secret, encrypted by the host (ASP.NET Core data protection).</summary>
    public required string ProtectedSecret { get; init; }

    /// <summary>True once the enrolment was confirmed with a valid code; false while it waits for the confirmation.</summary>
    public bool Enabled { get; init; }

    /// <summary>The time step of the last accepted code. A code of this step or an older one is refused (replay).</summary>
    public long LastUsedStep { get; init; }

    /// <summary>The PBKDF2 hashes of the recovery codes that are not used yet.</summary>
    public IReadOnlyList<string> RecoveryCodeHashes { get; init; } = [];

    public DateTime CreatedAt { get; init; }

    public DateTime? EnabledAt { get; init; }

    /// <summary>The version for <see cref="ITwoFactorStore.TryUpdateAsync"/>: a change of another node or login is not overwritten.</summary>
    public int Version { get; init; }
}
