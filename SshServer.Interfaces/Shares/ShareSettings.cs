namespace SshServer.Interfaces.Shares;

/// <summary>
/// <see cref="ServerSettings.Shares"/> (#70): whether the users may create share links, and their limits. Null or not
/// <see cref="Enabled"/>: no share link works (the web client must be on too).
/// </summary>
public sealed record ShareSettings
{
    /// <summary>The users of the web client may create share links. Default false.</summary>
    public bool Enabled { get; set; }

    /// <summary>The longest life of a share in days; a share must have an expiry within it. 0: no limit.</summary>
    public int MaxLifetimeDays { get; set; }

    /// <summary>Every share must have a password.</summary>
    public bool RequirePassword { get; set; }

    public const int MaxLifetimeDaysLimit = 3650;
}
