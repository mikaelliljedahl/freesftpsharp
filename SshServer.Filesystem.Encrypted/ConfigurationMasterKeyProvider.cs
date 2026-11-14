using Microsoft.Extensions.Options;

namespace SshServer.Filesystem.Encrypted;

/// <summary>
/// The master keys from configuration (<see cref="EncryptedStorageOptions"/>): <c>Storage:Encryption:Keys</c> and
/// <c>Storage:Encryption:ActiveKeyId</c>. The keys are read once, at the first use.
/// </summary>
public sealed class ConfigurationMasterKeyProvider : IMasterKeyProvider
{
    private readonly Lazy<MasterKeyLoader.Result> _keys;

    public ConfigurationMasterKeyProvider(IOptions<EncryptedStorageOptions> options)
    {
        _keys = new Lazy<MasterKeyLoader.Result>(() => MasterKeyLoader.Load(options.Value));
    }

    public ValueTask<MasterKey> GetActiveKeyAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var keys = _keys.Value;
        if (keys.Problems.Count > 0 || keys.ActiveKey == null)
            throw new InvalidOperationException("The encryption keys are not valid: " + string.Join(" ", keys.Problems));
        return ValueTask.FromResult(keys.ActiveKey);
    }

    public ValueTask<MasterKey?> FindKeyAsync(ReadOnlyMemory<byte> keyId, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return ValueTask.FromResult(_keys.Value.Keys.FirstOrDefault(k => k.HasKeyId(keyId.Span)));
    }
}
