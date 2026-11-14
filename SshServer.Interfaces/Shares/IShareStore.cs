namespace SshServer.Interfaces.Shares;

/// <summary>
/// The store of the share links (#70), in the settings database. It only stores: the rules (who may create or revoke a
/// share, the validation, the access) are in the web client and the administration. The returned objects are copies.
/// </summary>
public interface IShareStore
{
    /// <summary>The shares of one user (by <see cref="Share.UserId"/>), or of every user when <paramref name="userId"/> is null; newest first.</summary>
    Task<IReadOnlyList<Share>> ListAsync(int? userId, CancellationToken ct);

    Task<Share?> GetAsync(string id, CancellationToken ct);

    Task AddAsync(Share share, CancellationToken ct);

    Task<bool> RemoveAsync(string id, CancellationToken ct);

    /// <summary>
    /// Counts one use: adds 1 to <see cref="Share.UsedCount"/> and sets <see cref="Share.LastUsedAt"/>, only when the share
    /// exists and is not used up (<see cref="Share.MaxUses"/>). The check and the change are one step, so two downloads at the
    /// same time cannot both take the last use, also on two nodes. False: the share is used up or removed.
    /// </summary>
    Task<bool> TryUseAsync(string id, DateTime usedAtUtc, CancellationToken ct);
}
