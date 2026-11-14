using SshServer.Filesystem.Encrypted;

namespace FreeSftpSharp.Tests.Storage.Encrypted;

/// <summary>Master keys for the tests of the encrypted storage.</summary>
internal static class TestKeys
{
    /// <summary>The master key of the known-answer vectors: the bytes 0x00..0x1f.</summary>
    public static readonly byte[] KatKey = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    public const string KatKeyId = "kat-key-1";

    public static readonly byte[] KeyA = Enumerable.Range(0, 32).Select(i => (byte)(0xA0 ^ i)).ToArray();
    public static readonly byte[] KeyB = Enumerable.Range(0, 32).Select(i => (byte)(0xB0 ^ i)).ToArray();

    /// <summary>A key provider from configuration options with these keys.</summary>
    public static ConfigurationMasterKeyProvider Provider(string activeId, params (string Id, byte[] Key)[] keys)
        => new(Microsoft.Extensions.Options.Options.Create(Options(activeId, keys)));

    public static EncryptedStorageOptions Options(string activeId, params (string Id, byte[] Key)[] keys) => new()
    {
        Enabled = true,
        ActiveKeyId = activeId,
        Keys = keys.Select(k => new EncryptionKeyOptions { Id = k.Id, Key = Convert.ToBase64String(k.Key) }).ToList(),
    };
}
