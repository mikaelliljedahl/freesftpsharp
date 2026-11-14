namespace SshServer.Interfaces.TwoFactor;

/// <summary>The result of a second-factor check. Every value except the two successes is a failure for the client.</summary>
public enum TwoFactorCheck
{
    /// <summary>A valid TOTP code that was not used before.</summary>
    Valid,

    /// <summary>A valid recovery code; it is used up now.</summary>
    RecoveryCode,

    /// <summary>A wrong code.</summary>
    Invalid,

    /// <summary>A code that was valid but is used already (the same code or an older one).</summary>
    Replayed,

    /// <summary>Too many wrong codes for this subject lately; the code was not checked.</summary>
    LockedOut,

    /// <summary>The subject has no confirmed second factor.</summary>
    NotEnabled,
}

/// <summary>
/// The second factor as the protocols and the admin login use it (issue #63). The implementation is the two-factor
/// service of <c>SshServer.TwoFactor</c>; without it no subject has a second factor.
/// </summary>
public interface ITwoFactorVerifier
{
    /// <summary>True when the subject has a confirmed TOTP enrolment, so a login needs a code.</summary>
    Task<bool> IsEnabledAsync(TwoFactorSubject subject, CancellationToken ct);

    /// <summary>
    /// Checks a TOTP code or a recovery code. A valid code works once: the code (and older ones) or the recovery code
    /// is refused afterwards. Wrong codes count for a per-subject limit.
    /// </summary>
    Task<TwoFactorCheck> VerifyAsync(TwoFactorSubject subject, string? code, CancellationToken ct);
}
