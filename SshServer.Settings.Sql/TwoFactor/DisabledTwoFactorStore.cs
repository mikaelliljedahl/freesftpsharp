using SshServer.Interfaces.TwoFactor;

namespace SshServer.Settings.Sql.TwoFactor;

/// <summary>
/// The two-factor store of the obsolete LiteDB settings provider: it has no table for the secrets, so nobody has a second
/// factor and a setup is refused (an in-memory secret would be lost at a restart and turn the second factor off).
/// </summary>
public sealed class DisabledTwoFactorStore : ITwoFactorStore
{
    public Task<TwoFactorEnrolment?> GetAsync(TwoFactorSubject subject, CancellationToken ct) => Task.FromResult<TwoFactorEnrolment?>(null);

    public Task<TwoFactorEnrolment> ReplaceAsync(TwoFactorEnrolment enrolment, CancellationToken ct) =>
        throw new NotSupportedException("Two-factor authentication needs the SQLite settings database (Settings:Provider).");

    public Task<bool> TryUpdateAsync(TwoFactorEnrolment enrolment, CancellationToken ct) => Task.FromResult(false);

    public Task<bool> RemoveAsync(TwoFactorSubject subject, CancellationToken ct) => Task.FromResult(false);

    public Task<IReadOnlySet<int>> ListEnabledAsync(TwoFactorSubjectKind kind, CancellationToken ct) =>
        Task.FromResult<IReadOnlySet<int>>(new HashSet<int>());
}
