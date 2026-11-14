using Microsoft.EntityFrameworkCore;
using SshServer.Interfaces.TwoFactor;

namespace SshServer.Settings.Sql.TwoFactor;

/// <summary>
/// <see cref="ITwoFactorStore"/> in the table TwoFactorEnrolments of the settings database. The settings repository
/// creates and migrates the database at the start; this class only reads and writes rows, each call with its own
/// context. <see cref="TryUpdateAsync"/> uses the <see cref="TwoFactorRecord.Version"/> column as concurrency token, so
/// two logins with the same code (also on two nodes) cannot both save it.
/// </summary>
public sealed class SqlTwoFactorStore : ITwoFactorStore
{
    private readonly DbContextOptions<SettingsDbContext> _options;

    public SqlTwoFactorStore(DbContextOptions<SettingsDbContext> options)
    {
        _options = options;
    }

    private SettingsDbContext CreateContext() => new(_options);

    public async Task<TwoFactorEnrolment?> GetAsync(TwoFactorSubject subject, CancellationToken ct)
    {
        await using var db = CreateContext();
        var record = await Find(db.TwoFactorEnrolments.AsNoTracking(), subject).FirstOrDefaultAsync(ct);
        return record == null ? null : ToModel(subject, record);
    }

    public async Task<TwoFactorEnrolment> ReplaceAsync(TwoFactorEnrolment enrolment, CancellationToken ct)
    {
        await using var db = CreateContext();
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        await Find(db.TwoFactorEnrolments, enrolment.Subject).ExecuteDeleteAsync(ct);
        var record = new TwoFactorRecord
        {
            UserId = enrolment.Subject.Kind == TwoFactorSubjectKind.User ? enrolment.Subject.Id : null,
            AdminId = enrolment.Subject.Kind == TwoFactorSubjectKind.Admin ? enrolment.Subject.Id : null,
            Version = 1,
        };
        Apply(enrolment, record);
        db.TwoFactorEnrolments.Add(record);
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);
        return ToModel(enrolment.Subject, record);
    }

    public async Task<bool> TryUpdateAsync(TwoFactorEnrolment enrolment, CancellationToken ct)
    {
        await using var db = CreateContext();
        var record = await Find(db.TwoFactorEnrolments, enrolment.Subject).FirstOrDefaultAsync(ct);
        if (record == null || record.Version != enrolment.Version)
            return false;
        Apply(enrolment, record);
        record.Version = enrolment.Version + 1;
        try
        {
            await db.SaveChangesAsync(ct);
            return true;
        }
        catch (DbUpdateConcurrencyException)
        {
            return false; // another update came between the read and the save
        }
    }

    public async Task<bool> RemoveAsync(TwoFactorSubject subject, CancellationToken ct)
    {
        await using var db = CreateContext();
        return await Find(db.TwoFactorEnrolments, subject).ExecuteDeleteAsync(ct) > 0;
    }

    public async Task<IReadOnlySet<int>> ListEnabledAsync(TwoFactorSubjectKind kind, CancellationToken ct)
    {
        await using var db = CreateContext();
        var enabled = db.TwoFactorEnrolments.AsNoTracking().Where(r => r.Enabled);
        var ids = kind == TwoFactorSubjectKind.User
            ? await enabled.Where(r => r.UserId != null).Select(r => r.UserId!.Value).ToListAsync(ct)
            : await enabled.Where(r => r.AdminId != null).Select(r => r.AdminId!.Value).ToListAsync(ct);
        return ids.ToHashSet();
    }

    private static IQueryable<TwoFactorRecord> Find(IQueryable<TwoFactorRecord> records, TwoFactorSubject subject) =>
        subject.Kind == TwoFactorSubjectKind.User
            ? records.Where(r => r.UserId == subject.Id)
            : records.Where(r => r.AdminId == subject.Id);

    private static void Apply(TwoFactorEnrolment enrolment, TwoFactorRecord record)
    {
        record.ProtectedSecret = enrolment.ProtectedSecret;
        record.Enabled = enrolment.Enabled;
        record.LastUsedStep = enrolment.LastUsedStep;
        record.RecoveryCodeHashes = enrolment.RecoveryCodeHashes.ToList();
        record.CreatedAt = enrolment.CreatedAt;
        record.EnabledAt = enrolment.EnabledAt;
    }

    private static TwoFactorEnrolment ToModel(TwoFactorSubject subject, TwoFactorRecord record) => new()
    {
        Subject = subject,
        ProtectedSecret = record.ProtectedSecret,
        Enabled = record.Enabled,
        LastUsedStep = record.LastUsedStep,
        RecoveryCodeHashes = record.RecoveryCodeHashes.ToList(),
        CreatedAt = DateTime.SpecifyKind(record.CreatedAt, DateTimeKind.Utc),
        EnabledAt = record.EnabledAt is { } at ? DateTime.SpecifyKind(at, DateTimeKind.Utc) : null,
        Version = record.Version,
    };
}
