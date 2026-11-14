namespace SshServer.Interfaces.TwoFactor;

/// <summary>
/// The store of the TOTP enrolments in the settings database. It only stores: the rules (codes, replay, recovery codes)
/// are in the two-factor service of <c>SshServer.TwoFactor</c>. The enrolment of a removed user or administrator is
/// removed with it.
/// </summary>
public interface ITwoFactorStore
{
    /// <summary>The enrolment of the subject (confirmed or not), or null.</summary>
    Task<TwoFactorEnrolment?> GetAsync(TwoFactorSubject subject, CancellationToken ct);

    /// <summary>Saves a new enrolment of the subject; it replaces the stored one. Returns the saved enrolment with its version.</summary>
    Task<TwoFactorEnrolment> ReplaceAsync(TwoFactorEnrolment enrolment, CancellationToken ct);

    /// <summary>
    /// Saves the enrolment when the stored one still has <see cref="TwoFactorEnrolment.Version"/>, and increments the
    /// version. False when another change came first or when there is no enrolment: read it again.
    /// </summary>
    Task<bool> TryUpdateAsync(TwoFactorEnrolment enrolment, CancellationToken ct);

    /// <summary>Removes the enrolment of the subject. False when there is none.</summary>
    Task<bool> RemoveAsync(TwoFactorSubject subject, CancellationToken ct);

    /// <summary>The ids of the subjects of a kind with a confirmed enrolment (for the lists of the admin UI).</summary>
    Task<IReadOnlySet<int>> ListEnabledAsync(TwoFactorSubjectKind kind, CancellationToken ct);
}
