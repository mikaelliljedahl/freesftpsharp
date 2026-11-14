namespace SshServer.Interfaces.Api;

/// <summary>
/// The store of the REST API keys (#67), in the settings database. It only stores: the rules (who may create or revoke
/// a key, the key format, the hash) are in the API. The returned objects are copies.
/// </summary>
public interface IApiKeyStore
{
    /// <summary>The keys of one administrator, or of every administrator when <paramref name="adminId"/> is null.</summary>
    Task<IReadOnlyList<ApiKey>> ListAsync(int? adminId, CancellationToken ct);

    Task<ApiKey?> GetAsync(int id, CancellationToken ct);

    /// <summary>The key with this hash (<see cref="ApiKey.KeyHash"/>), or null.</summary>
    Task<ApiKey?> FindByHashAsync(string keyHash, CancellationToken ct);

    /// <summary>Adds a copy and sets <see cref="ApiKey.Id"/>. False when the administrator has a key with the name already.</summary>
    Task<bool> AddAsync(ApiKey key, CancellationToken ct);

    Task<bool> RemoveAsync(int id, CancellationToken ct);

    /// <summary>Saves <see cref="ApiKey.LastUsedAt"/>.</summary>
    Task TouchAsync(int id, DateTime usedAtUtc, CancellationToken ct);
}

/// <summary>
/// The signing key of the REST API bearer tokens (#67), in the settings database, so every node that shares the
/// database accepts the tokens of the others. The value is encrypted by the caller.
/// </summary>
public interface IApiSigningKeyStore
{
    /// <summary>
    /// The stored key, or <paramref name="create"/>() stored as the key when there is none yet. Two nodes that start
    /// together get the same key.
    /// </summary>
    Task<string> GetOrAddAsync(Func<string> create, CancellationToken ct);
}
