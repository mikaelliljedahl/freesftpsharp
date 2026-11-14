namespace SshServer.Settings.Sql.TwoFactor;

/// <summary>
/// The row of a TOTP enrolment (table TwoFactorEnrolments, issue #63): for one user (<see cref="UserId"/>) or one
/// administrator (<see cref="AdminId"/>), removed with it. Only <see cref="SqlTwoFactorStore"/> uses it; the model of the
/// rest of the server is <see cref="Interfaces.TwoFactor.TwoFactorEnrolment"/>.
/// </summary>
public class TwoFactorRecord
{
    public int Id { get; set; }

    public int? UserId { get; set; }

    public int? AdminId { get; set; }

    /// <summary>The TOTP secret encrypted with ASP.NET Core data protection.</summary>
    public string ProtectedSecret { get; set; } = string.Empty;

    public bool Enabled { get; set; }

    public long LastUsedStep { get; set; }

    /// <summary>The PBKDF2 hashes of the unused recovery codes.</summary>
    public List<string> RecoveryCodeHashes { get; set; } = [];

    public DateTime CreatedAt { get; set; }

    public DateTime? EnabledAt { get; set; }

    /// <summary>The concurrency token: each update increments it.</summary>
    public int Version { get; set; }
}
