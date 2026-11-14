using System.Collections.Concurrent;
using SshServer.Interfaces.TwoFactor;

namespace FreeSftpSharp.Tests.Infrastructure;

/// <summary>An <see cref="ITwoFactorStore"/> in memory for the tests, with the same version rule as the SQL store.</summary>
public sealed class InMemoryTwoFactorStore : ITwoFactorStore
{
    private readonly ConcurrentDictionary<TwoFactorSubject, TwoFactorEnrolment> _enrolments = new();

    public Task<TwoFactorEnrolment?> GetAsync(TwoFactorSubject subject, CancellationToken ct) =>
        Task.FromResult(_enrolments.TryGetValue(subject, out var e) ? e : null);

    public Task<TwoFactorEnrolment> ReplaceAsync(TwoFactorEnrolment enrolment, CancellationToken ct)
    {
        var saved = enrolment with { Version = 1 };
        _enrolments[enrolment.Subject] = saved;
        return Task.FromResult(saved);
    }

    public Task<bool> TryUpdateAsync(TwoFactorEnrolment enrolment, CancellationToken ct)
    {
        lock (_enrolments)
        {
            if (!_enrolments.TryGetValue(enrolment.Subject, out var stored) || stored.Version != enrolment.Version)
                return Task.FromResult(false);
            _enrolments[enrolment.Subject] = enrolment with { Version = enrolment.Version + 1 };
            return Task.FromResult(true);
        }
    }

    public Task<bool> RemoveAsync(TwoFactorSubject subject, CancellationToken ct) => Task.FromResult(_enrolments.TryRemove(subject, out _));

    public Task<IReadOnlySet<int>> ListEnabledAsync(TwoFactorSubjectKind kind, CancellationToken ct) =>
        Task.FromResult<IReadOnlySet<int>>(_enrolments.Values.Where(e => e.Enabled && e.Subject.Kind == kind).Select(e => e.Subject.Id).ToHashSet());
}
